// Bazarish project (c) 2026
#include "bazarish/Sam.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace bazarish::sam {

namespace {

// EdDSA-SHA512-Ed25519 per the I2P common structures specification. Always sent:
// the router's own default is DSA-SHA1, and a signature type it cannot read
// degrades to that default with nothing but a log line.
constexpr int kEd25519SignatureType = 7;

// NETDB_STORE_TYPE values for i2cp.leaseSetType.
constexpr int kEncryptedLeaseSetType = 5;
constexpr int kStandardLeaseSetType = 3;

// A control reply cannot exceed the router's own line buffer, so anything longer
// is not a reply. Without a bound, whatever holds the port decides how much
// memory this process spends.
constexpr std::size_t kMaxReplyLineBytes = 8192;

// Bound on a control exchange that is not waiting for tunnels. Only stops a
// wedged router from hanging a caller; it is not a latency target.
constexpr int kControlIoTimeoutSeconds = 240;

// i2pd drops anything larger rather than fragmenting it.
constexpr std::size_t kMaxDatagramBytes = 32768;

// How often the watch looks at the control connection, and how long it waits
// before trying to rebuild a session the router has dropped.
constexpr int kWatchPollMs = 1000;
constexpr int kRebuildDelaySeconds = 5;

constexpr int kListenBacklog = 16;

// The version line of the datagram header. The router skips this token without
// reading it, but the field is part of the format.
constexpr const char* kDatagramHeaderVersion = "3.0";

constexpr const char* kTransientDestination = "TRANSIENT";

// Half of the first byte of a loopback address in host order.
constexpr std::uint32_t kLoopbackFirstOctet = 127;

class Fd {
public:
    explicit Fd(const int fd = -1)
        : fd_(fd)
    {
    }
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    int release()
    {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }
    void reset(const int fd = -1)
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

void setSocketTimeouts(const int fd, const int seconds)
{
    timeval timeout{};
    timeout.tv_sec = seconds;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0
        || ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        throw Error(Result::eI2pError, "SAM: could not set socket timeouts");
    }
}

sockaddr_in loopbackAddress(const std::string& host, const std::uint16_t port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        throw Error(Result::eI2pError, "SAM: " + host + " is not an IPv4 address");
    }
    // The router is handed the private keys of every destination it operates.
    // That is a thing to do on this machine and nowhere else.
    if ((ntohl(addr.sin_addr.s_addr) >> 24) != kLoopbackFirstOctet) {
        throw Error(Result::eI2pError, "SAM: " + host + " is not a loopback address");
    }
    return addr;
}

int openControlSocket(const std::string& host, const std::uint16_t port)
{
    const sockaddr_in addr = loopbackAddress(host, port);
    Fd fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no socket");
    }
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw Error(Result::eI2pError,
            "SAM: no router at " + host + ":" + std::to_string(port));
    }
    setSocketTimeouts(fd.get(), kControlIoTimeoutSeconds);
    return fd.release();
}

int openLocalUdpSocket(std::uint16_t& boundPort)
{
    Fd fd(::socket(AF_INET, SOCK_DGRAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no datagram socket");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw Error(Result::eI2pError, "SAM: could not bind a datagram socket");
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        throw Error(Result::eI2pError, "SAM: could not read the datagram port");
    }
    boundPort = ntohs(bound.sin_port);
    return fd.release();
}

int openLocalListener(std::uint16_t& boundPort)
{
    Fd fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no listening socket");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0
        || ::listen(fd.get(), kListenBacklog) != 0) {
        throw Error(Result::eI2pError, "SAM: could not listen for forwarded streams");
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        throw Error(Result::eI2pError, "SAM: could not read the listening port");
    }
    boundPort = ntohs(bound.sin_port);
    return fd.release();
}

void writeAllFd(const int fd, const void* data, const std::size_t size)
{
    const auto* cursor = static_cast<const unsigned char*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const ssize_t written = ::write(fd, cursor + sent, size - sent);
        if (written <= 0) {
            throw Error(Result::eI2pError, "SAM: the connection went away while writing");
        }
        sent += static_cast<std::size_t>(written);
    }
}

// One line, a byte at a time: the socket carries stream payload right after the
// reply, and a read that overshoots would swallow it.
std::string readLineFd(const int fd)
{
    std::string line;
    while (true) {
        char c = 0;
        const ssize_t got = ::read(fd, &c, 1);
        if (got <= 0) {
            throw Error(Result::eI2pError, "SAM: the connection went away while reading");
        }
        if (c == '\n') {
            break;
        }
        if (c != '\r') {
            line.push_back(c);
        }
        if (line.size() > kMaxReplyLineBytes) {
            throw Error(Result::eI2pError, "SAM: reply line over "
                    + std::to_string(kMaxReplyLineBytes) + " bytes");
        }
    }
    return line;
}

Result resultFromString(const std::string& text)
{
    if (text == "OK") {
        return Result::eOk;
    }
    if (text == "INVALID_ID") {
        return Result::eInvalidId;
    }
    if (text == "DUPLICATED_ID") {
        return Result::eDuplicatedId;
    }
    if (text == "INVALID_KEY") {
        return Result::eInvalidKey;
    }
    if (text == "CANT_REACH_PEER") {
        return Result::eCantReachPeer;
    }
    if (text == "I2P_ERROR") {
        return Result::eI2pError;
    }
    return Result::eUnknown;
}

// Splits a reply into key=value pairs after the two reply words. A value may be
// quoted, which is how a MESSAGE with spaces in it arrives.
std::map<std::string, std::string> parseReply(const std::string& line)
{
    std::map<std::string, std::string> values;
    std::size_t pos = 0;
    int word = 0;
    while (pos < line.size()) {
        while (pos < line.size() && line[pos] == ' ') {
            ++pos;
        }
        if (pos >= line.size()) {
            break;
        }
        if (word >= 2) {
            const std::size_t equals = line.find('=', pos);
            if (equals == std::string::npos) {
                break;
            }
            const std::string key = line.substr(pos, equals - pos);
            std::string value;
            std::size_t cursor = equals + 1;
            if (cursor < line.size() && line[cursor] == '"') {
                ++cursor;
                while (cursor < line.size() && line[cursor] != '"') {
                    value.push_back(line[cursor]);
                    ++cursor;
                }
                ++cursor;
            } else {
                while (cursor < line.size() && line[cursor] != ' ') {
                    value.push_back(line[cursor]);
                    ++cursor;
                }
            }
            values[key] = value;
            pos = cursor;
            continue;
        }
        while (pos < line.size() && line[pos] != ' ') {
            ++pos;
        }
        ++word;
    }
    return values;
}

bool hasReplyPrefix(const std::string& line, const std::string& prefix)
{
    return line.size() >= prefix.size() && line.compare(0, prefix.size(), prefix) == 0;
}

std::map<std::string, std::string> commandFd(
    const int fd, const std::string& line, const std::string& expectedPrefix)
{
    writeAllFd(fd, line.data(), line.size());
    const std::string reply = readLineFd(fd);
    if (!hasReplyPrefix(reply, expectedPrefix)) {
        throw Error(Result::eUnknown, "SAM: unexpected reply: " + reply);
    }
    std::map<std::string, std::string> values = parseReply(reply);
    const auto result = values.find("RESULT");
    if (result != values.end()) {
        const Result code = resultFromString(result->second);
        if (code != Result::eOk) {
            const auto message = values.find("MESSAGE");
            throw Error(code,
                "SAM: " + expectedPrefix + " " + result->second
                    + (message != values.end() ? ": " + message->second : std::string()));
        }
    }
    return values;
}

std::string handshake(const int fd)
{
    const std::map<std::string, std::string> reply
        = commandFd(fd, "HELLO VERSION MIN=3.1 MAX=3.3\n", "HELLO REPLY");
    const auto version = reply.find("VERSION");
    if (version == reply.end()) {
        throw Error(Result::eUnknown, "SAM: the handshake named no version");
    }
    return version->second;
}

std::string styleName(const Style style)
{
    switch (style) {
        case Style::eStream:
            return "STREAM";
        case Style::eDatagram:
            return "DATAGRAM";
        case Style::eRaw:
            return "RAW";
    }
    throw Error(Result::eI2pError, "SAM: unknown session style");
}

// The tunnel profile as I2CP options. The mapping is the one the embedded engine
// uses, so a destination means the same thing on either transport.
std::string privacyOptions(const i2p::Privacy privacy)
{
    int length = 0;
    int variance = 0;
    switch (privacy) {
        case i2p::Privacy::eMinimal:
            length = 1;
            variance = 0;
            break;
        case i2p::Privacy::eMiddle:
            length = 1;
            variance = 1;
            break;
        case i2p::Privacy::eMax:
            length = 3;
            variance = 0;
            break;
    }
    std::ostringstream options;
    options << "inbound.length=" << length << " outbound.length=" << length
            << " inbound.lengthVariance=" << variance
            << " outbound.lengthVariance=" << variance;
    return options.str();
}

std::string tunnelQuantityOptions(int quantity)
{
    quantity = std::max(1, std::min(quantity, i2p::kMaxTunnelQuantity));
    const std::string count = std::to_string(quantity);
    return "inbound.quantity=" + count + " outbound.quantity=" + count;
}

std::string sessionCreateLine(const std::string& id, const SessionConfig& config,
    const std::uint16_t forwardUdpPort)
{
    std::ostringstream line;
    line << "SESSION CREATE STYLE=" << styleName(config.style) << " ID=" << id
         << " DESTINATION="
         << (config.privateKeys.empty() ? kTransientDestination : config.privateKeys)
         << " SIGNATURE_TYPE=" << kEd25519SignatureType << " i2cp.leaseSetType="
         << (config.leaseSet == i2p::LeaseSetKind::eEncrypted ? kEncryptedLeaseSetType
                                                              : kStandardLeaseSetType);
    if (!config.published) {
        // SAM creates every destination as public, so this option is the only way
        // to keep a dial-out destination out of the netDb.
        line << " i2cp.dontPublishLeaseSet=true";
    }
    line << " " << privacyOptions(config.privacy) << " "
         << tunnelQuantityOptions(config.tunnelQuantity);
    if (forwardUdpPort != 0) {
        line << " HOST=" << kDefaultHost << " PORT=" << forwardUdpPort;
    }
    line << "\n";
    return line.str();
}

// Waits for one of the socket's events; false on timeout.
bool waitReadable(const int fd, const int timeoutMs)
{
    pollfd watched{};
    watched.fd = fd;
    watched.events = POLLIN;
    const int ready = ::poll(&watched, 1, timeoutMs);
    return ready > 0;
}

}  // namespace

std::uint16_t RouterAddress::resolvedDatagramPort() const
{
    return datagramPort != 0 ? datagramPort
                             : static_cast<std::uint16_t>(controlPort - kDatagramPortBelowControl);
}

std::string_view toString(const Result result)
{
    switch (result) {
        case Result::eOk:
            return "OK";
        case Result::eInvalidId:
            return "INVALID_ID";
        case Result::eDuplicatedId:
            return "DUPLICATED_ID";
        case Result::eInvalidKey:
            return "INVALID_KEY";
        case Result::eCantReachPeer:
            return "CANT_REACH_PEER";
        case Result::eI2pError:
            return "I2P_ERROR";
        case Result::eUnknown:
            return "UNKNOWN";
    }
    return "UNKNOWN";
}

Error::Error(const Result result, const std::string& message)
    : std::runtime_error(message)
    , result_(result)
{
}

Result Error::result() const
{
    return result_;
}

std::string probe(const RouterAddress& router)
{
    const Fd control(openControlSocket(router.host, router.controlPort));
    return handshake(control.get());
}

Destination generateDestination(const RouterAddress& router)
{
    const Fd control(openControlSocket(router.host, router.controlPort));
    (void)handshake(control.get());
    const std::map<std::string, std::string> reply = commandFd(control.get(),
        "DEST GENERATE SIGNATURE_TYPE=" + std::to_string(kEd25519SignatureType) + "\n",
        "DEST REPLY");
    const auto pub = reply.find("PUB");
    const auto priv = reply.find("PRIV");
    if (pub == reply.end() || priv == reply.end()) {
        throw Error(Result::eUnknown, "SAM: DEST REPLY carried no keys");
    }
    return Destination{pub->second, priv->second};
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

Stream::Stream(const int fd)
    : fd_(fd)
{
}

Stream::~Stream()
{
    close();
}

std::size_t Stream::readSome(void* buffer, const std::size_t size)
{
    if (fd_ < 0) {
        return 0;
    }
    const ssize_t got = ::read(fd_, buffer, size);
    if (got < 0) {
        throw Error(Result::eI2pError, "SAM: stream read failed");
    }
    return static_cast<std::size_t>(got);
}

void Stream::readExact(void* buffer, const std::size_t size)
{
    auto* cursor = static_cast<unsigned char*>(buffer);
    std::size_t read = 0;
    while (read < size) {
        const std::size_t got = readSome(cursor + read, size - read);
        if (got == 0) {
            throw Error(Result::eI2pError, "SAM: stream closed before the read completed");
        }
        read += got;
    }
}

void Stream::writeAll(const void* data, const std::size_t size)
{
    if (fd_ < 0) {
        throw Error(Result::eI2pError, "SAM: write to a closed stream");
    }
    writeAllFd(fd_, data, size);
}

std::size_t Stream::pendingBytes() const
{
    if (fd_ < 0) {
        return 0;
    }
    int queued = 0;
    if (::ioctl(fd_, TIOCOUTQ, &queued) != 0 || queued < 0) {
        return 0;
    }
    return static_cast<std::size_t>(queued);
}

void Stream::close()
{
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct Session::Impl {
    RouterAddress router;
    SessionConfig config;
    std::chrono::seconds readyTimeout{0};
    std::string id;
    std::string publicDestination;
    std::string privateKeys;

    mutable std::mutex mutex;
    Fd control;
    Fd forward;
    Fd listener;
    Fd datagrams;
    std::uint16_t listenPort = 0;
    std::uint16_t datagramPort = 0;
    std::atomic<bool> listening{false};
    std::atomic<bool> alive{false};

    std::atomic<bool> stopping{false};
    std::thread watch;

    // Opens the control connection and creates the session on it. The router
    // answers only once the destination has tunnels, so this is also the wait
    // for readiness.
    void create()
    {
        Fd control(openControlSocket(router.host, router.controlPort));
        (void)handshake(control.get());
        setSocketTimeouts(control.get(), static_cast<int>(readyTimeout.count()));
        const std::map<std::string, std::string> created = commandFd(control.get(),
            sessionCreateLine(id, config, datagramPort), "SESSION STATUS");
        setSocketTimeouts(control.get(), kControlIoTimeoutSeconds);
        const auto keys = created.find("DESTINATION");
        if (keys == created.end()) {
            throw Error(Result::eUnknown, "SAM: SESSION STATUS carried no destination");
        }
        // What comes back is the private blob. The shareable half has to be
        // asked for separately.
        const std::map<std::string, std::string> naming
            = commandFd(control.get(), "NAMING LOOKUP NAME=ME\n", "NAMING REPLY");
        const auto value = naming.find("VALUE");
        if (value == naming.end()) {
            throw Error(Result::eUnknown, "SAM: NAMING REPLY carried no destination");
        }
        const std::lock_guard<std::mutex> lock(mutex);
        privateKeys = keys->second;
        publicDestination = value->second;
        this->control.reset(control.release());
        alive = true;
    }

    // STREAM FORWARD on a connection of its own: the command claims the socket
    // it arrives on, and the session's own connection must stay a session.
    void startForwarding()
    {
        Fd forwarder(openControlSocket(router.host, router.controlPort));
        (void)handshake(forwarder.get());
        (void)commandFd(forwarder.get(),
            "STREAM FORWARD ID=" + id + " PORT=" + std::to_string(listenPort) + " HOST="
                + kDefaultHost + " SILENT=false\n",
            "STREAM STATUS");
        const std::lock_guard<std::mutex> lock(mutex);
        forward.reset(forwarder.release());
    }

    // The router drops a session with its control connection, so losing that
    // connection is the one thing worth watching for.
    void watchLoop()
    {
        while (!stopping) {
            int fd = -1;
            {
                const std::lock_guard<std::mutex> lock(mutex);
                fd = control.get();
            }
            if (fd < 0) {
                break;
            }
            if (!waitReadable(fd, kWatchPollMs)) {
                continue;
            }
            char probe = 0;
            const ssize_t got = ::recv(fd, &probe, 1, MSG_PEEK);
            if (got > 0) {
                continue;  // an unsolicited line; nothing this session asked for
            }
            if (stopping) {
                break;
            }
            alive = false;
            bazarish::log::warn("i2p: the router dropped SAM session {}, rebuilding", id);
            rebuild();
        }
    }

    void rebuild()
    {
        while (!stopping) {
            try {
                {
                    const std::lock_guard<std::mutex> lock(mutex);
                    control.reset();
                    forward.reset();
                    // The keys the router handed back keep the address across the
                    // rebuild, even for a destination that started out transient.
                    config.privateKeys = privateKeys;
                }
                create();
                if (listening) {
                    startForwarding();
                }
                bazarish::log::info("i2p: SAM session {} is back", id);
                return;
            } catch (const std::exception& error) {
                bazarish::log::warn("i2p: SAM session {} not back yet: {}", id, error.what());
            }
            for (int waited = 0; waited < kRebuildDelaySeconds && !stopping; ++waited) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
};

Session::Session(RouterAddress router, SessionConfig config, const std::chrono::seconds readyTimeout)
    : impl_(std::make_unique<Impl>())
{
    impl_->router = std::move(router);
    impl_->config = std::move(config);
    impl_->readyTimeout = readyTimeout;
    // Unique per router, not just per process: several daemons share one router.
    impl_->id = "bazarish-" + toHex(randomBytes(8));
    if (impl_->config.style != Style::eStream) {
        impl_->datagrams.reset(openLocalUdpSocket(impl_->datagramPort));
    }
    impl_->create();
    impl_->watch = std::thread([impl = impl_.get()]() { impl->watchLoop(); });
}

Session::~Session()
{
    impl_->stopping = true;
    if (impl_->watch.joinable()) {
        impl_->watch.join();
    }
}

const std::string& Session::publicDestination() const
{
    return impl_->publicDestination;
}

const std::string& Session::privateKeys() const
{
    return impl_->privateKeys;
}

std::string Session::routingHost() const
{
    return i2p::routingHost(impl_->publicDestination, impl_->config.leaseSet);
}

bool Session::alive() const
{
    return impl_->alive;
}

std::unique_ptr<Stream> Session::connect(
    const std::string& destination, const std::chrono::seconds timeout)
{
    if (!impl_->alive) {
        throw Error(Result::eInvalidId, "SAM: the session is down");
    }
    Fd stream(openControlSocket(impl_->router.host, impl_->router.controlPort));
    (void)handshake(stream.get());
    setSocketTimeouts(stream.get(), static_cast<int>(timeout.count()));
    (void)commandFd(stream.get(),
        "STREAM CONNECT ID=" + impl_->id + " DESTINATION=" + destination + " SILENT=false\n",
        "STREAM STATUS");
    // From here the socket is the stream itself, and a read blocks for as long
    // as the caller is willing to wait rather than for a control timeout.
    setSocketTimeouts(stream.get(), 0);
    return std::make_unique<Stream>(stream.release());
}

void Session::listen()
{
    if (impl_->listening) {
        return;
    }
    impl_->listener.reset(openLocalListener(impl_->listenPort));
    impl_->startForwarding();
    impl_->listening = true;
}

std::unique_ptr<Stream> Session::accept(
    std::string& peerDestination, const std::chrono::milliseconds timeout)
{
    if (!impl_->listening) {
        throw Error(Result::eI2pError, "SAM: accept before listen");
    }
    if (!waitReadable(impl_->listener.get(), static_cast<int>(timeout.count()))) {
        return nullptr;
    }
    Fd incoming(::accept(impl_->listener.get(), nullptr, nullptr));
    if (!incoming.valid()) {
        throw Error(Result::eI2pError, "SAM: could not take a forwarded stream");
    }
    setSocketTimeouts(incoming.get(), kControlIoTimeoutSeconds);
    // The router names the caller on the first line and then gets out of the way.
    const std::string peerLine = readLineFd(incoming.get());
    peerDestination = peerLine.substr(0, peerLine.find(' '));
    setSocketTimeouts(incoming.get(), 0);
    return std::make_unique<Stream>(incoming.release());
}

void Session::sendDatagram(
    const std::string& destination, const void* data, const std::size_t size)
{
    if (impl_->config.style == Style::eStream) {
        throw Error(Result::eI2pError, "SAM: datagram on a stream session");
    }
    if (size > kMaxDatagramBytes) {
        throw Error(Result::eI2pError, "SAM: datagram over "
                + std::to_string(kMaxDatagramBytes) + " bytes");
    }
    const std::string header = std::string(kDatagramHeaderVersion) + " " + impl_->id + " "
        + destination + "\n";
    std::vector<unsigned char> packet;
    packet.reserve(header.size() + size);
    packet.insert(packet.end(), header.begin(), header.end());
    const auto* bytes = static_cast<const unsigned char*>(data);
    packet.insert(packet.end(), bytes, bytes + size);

    const sockaddr_in addr
        = loopbackAddress(impl_->router.host, impl_->router.resolvedDatagramPort());
    const ssize_t sent = ::sendto(impl_->datagrams.get(), packet.data(), packet.size(), 0,
        reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if (sent < 0) {
        throw Error(Result::eI2pError, "SAM: could not hand the datagram to the router");
    }
}

std::vector<std::uint8_t> Session::receiveDatagram(
    std::string* const peerDestination, const std::chrono::milliseconds timeout)
{
    if (impl_->config.style == Style::eStream) {
        throw Error(Result::eI2pError, "SAM: datagram on a stream session");
    }
    if (!waitReadable(impl_->datagrams.get(), static_cast<int>(timeout.count()))) {
        return {};
    }
    std::vector<std::uint8_t> buffer(kMaxDatagramBytes);
    const ssize_t got = ::recv(impl_->datagrams.get(), buffer.data(), buffer.size(), 0);
    if (got <= 0) {
        return {};
    }
    buffer.resize(static_cast<std::size_t>(got));
    if (impl_->config.style == Style::eRaw) {
        return buffer;  // raw carries the payload and nothing else
    }
    // A repliable datagram arrives as the sender's destination, a newline, and
    // then the payload.
    const auto newline = std::find(buffer.begin(), buffer.end(), '\n');
    if (newline == buffer.end()) {
        throw Error(Result::eUnknown, "SAM: a repliable datagram named no sender");
    }
    if (peerDestination != nullptr) {
        peerDestination->assign(buffer.begin(), newline);
    }
    return std::vector<std::uint8_t>(newline + 1, buffer.end());
}

}  // namespace bazarish::sam
