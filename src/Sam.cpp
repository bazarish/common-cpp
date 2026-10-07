// Bazarish project (c) 2026
#include "bazarish/Sam.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/I2pAddress.hpp"
#include "bazarish/Log.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace bazarish::sam {

namespace {

constexpr int kEd25519SignatureType = 7;

// The NETDB_STORE_TYPE value for i2cp.leaseSetType.
constexpr int kEncryptedLeaseSetType = 5;

constexpr std::size_t kMaxReplyLineBytes = 8192;

constexpr int kControlIoTimeoutSeconds = 240;

// i2pd drops anything larger rather than fragmenting it.
constexpr std::size_t kMaxDatagramBytes = 32768;

constexpr int kWatchPollMs = 1000;
constexpr int kRebuildDelaySeconds = 5;

constexpr int kListenBacklog = 16;

constexpr int kMillisecondsPerSecond = 1000;

constexpr const char* kDatagramHeaderVersion = "3.0";

constexpr const char* kTransientDestination = "TRANSIENT";

constexpr std::uint32_t kLoopbackFirstOctet = 127;

#ifdef _WIN32

void ensureSockets()
{
    struct Winsock {
        Winsock()
        {
            WSADATA data{};
            if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
                throw Error(Result::eI2pError, "SAM: no socket library");
            }
        }
        ~Winsock() { WSACleanup(); }
    };
    static const Winsock started;
}

constexpr Socket kInvalidSocket = static_cast<Socket>(INVALID_SOCKET);

using NativeSocket = SOCKET;

constexpr int kNoSignal = 0;

void quietenSignals(Socket) { }

void closeSocket(const Socket socket) { ::closesocket(static_cast<SOCKET>(socket)); }

std::ptrdiff_t socketRead(const Socket socket, void* const buffer, const std::size_t size)
{
    return ::recv(static_cast<SOCKET>(socket), static_cast<char*>(buffer),
        static_cast<int>(size), 0);
}

std::ptrdiff_t socketWrite(const Socket socket, const void* const data, const std::size_t size)
{
    return ::send(static_cast<SOCKET>(socket), static_cast<const char*>(data),
        static_cast<int>(size), kNoSignal);
}

void setTimeoutOption(const Socket socket, const int option, const int seconds)
{
    const DWORD milliseconds = static_cast<DWORD>(seconds * kMillisecondsPerSecond);
    if (::setsockopt(static_cast<SOCKET>(socket), SOL_SOCKET, option,
            reinterpret_cast<const char*>(&milliseconds), sizeof milliseconds)
        != 0) {
        throw Error(Result::eI2pError, "SAM: could not set socket timeouts");
    }
}

std::ptrdiff_t socketSendTo(const Socket socket, const void* const data,
    const std::size_t size, const sockaddr_in& address)
{
    return ::sendto(static_cast<SOCKET>(socket), static_cast<const char*>(data),
        static_cast<int>(size), kNoSignal, reinterpret_cast<const sockaddr*>(&address),
        sizeof address);
}

bool socketReadable(const Socket socket, const int timeoutMs)
{
    WSAPOLLFD watched{};
    watched.fd = static_cast<SOCKET>(socket);
    watched.events = POLLRDNORM;
    return ::WSAPoll(&watched, 1, timeoutMs) > 0;
}

std::size_t socketSendQueue(Socket)
{
    return 0;
}

#else

void ensureSockets() {}

constexpr Socket kInvalidSocket = -1;

using NativeSocket = int;

void closeSocket(const Socket socket) { ::close(static_cast<int>(socket)); }

// A peer that has gone away must not raise SIGPIPE and take the process with it:
// Linux carries that on the call, the BSDs on the socket.
#ifdef MSG_NOSIGNAL
constexpr int kNoSignal = MSG_NOSIGNAL;
#else
constexpr int kNoSignal = 0;
#endif

void quietenSignals([[maybe_unused]] const Socket socket)
{
#ifdef SO_NOSIGPIPE
    const int wanted = 1;
    if (::setsockopt(static_cast<int>(socket), SOL_SOCKET, SO_NOSIGPIPE, &wanted, sizeof(wanted))
        != 0) {
        throw Error(Result::eI2pError, "SAM: socket would still signal on a closed peer");
    }
#endif
}

std::ptrdiff_t socketRead(const Socket socket, void* const buffer, const std::size_t size)
{
    return ::recv(static_cast<int>(socket), buffer, size, 0);
}

std::ptrdiff_t socketWrite(const Socket socket, const void* const data, const std::size_t size)
{
    return ::send(static_cast<int>(socket), data, size, kNoSignal);
}

void setTimeoutOption(const Socket socket, const int option, const int seconds)
{
    timeval timeout{};
    timeout.tv_sec = seconds;
    if (::setsockopt(static_cast<int>(socket), SOL_SOCKET, option, &timeout, sizeof(timeout))
        != 0) {
        throw Error(Result::eI2pError, "SAM: could not set socket timeouts");
    }
}

std::ptrdiff_t socketSendTo(const Socket socket, const void* const data,
    const std::size_t size, const sockaddr_in& address)
{
    return ::sendto(static_cast<int>(socket), data, size, kNoSignal,
        reinterpret_cast<const sockaddr*>(&address), sizeof address);
}

bool socketReadable(const Socket socket, const int timeoutMs)
{
    pollfd watched{};
    watched.fd = static_cast<int>(socket);
    watched.events = POLLIN;
    return ::poll(&watched, 1, timeoutMs) > 0;
}

std::size_t socketSendQueue(const Socket socket)
{
    int queued = 0;
    if (::ioctl(static_cast<int>(socket), TIOCOUTQ, &queued) != 0 || queued < 0) {
        return 0;
    }
    return static_cast<std::size_t>(queued);
}

#endif

NativeSocket native(const Socket socket)
{
    return static_cast<NativeSocket>(socket);
}

std::ptrdiff_t peekByte(const Socket socket)
{
    char probe = 0;
    return ::recv(native(socket), &probe, 1, MSG_PEEK);
}

class Held {
public:
    explicit Held(const Socket socket = kInvalidSocket)
        : socket_(socket)
    {
    }
    ~Held() { reset(); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;

    Socket get() const { return socket_; }
    bool valid() const { return socket_ != kInvalidSocket; }
    Socket release()
    {
        const Socket socket = socket_;
        socket_ = kInvalidSocket;
        return socket;
    }
    void reset(const Socket socket = kInvalidSocket)
    {
        if (socket_ != kInvalidSocket) {
            closeSocket(socket_);
        }
        socket_ = socket;
    }

private:
    Socket socket_;
};

void setSocketTimeouts(const Socket socket, const int seconds)
{
    setTimeoutOption(socket, SO_RCVTIMEO, seconds);
    setTimeoutOption(socket, SO_SNDTIMEO, seconds);
}

sockaddr_in loopbackAddress(const std::string& host, const std::uint16_t port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        throw Error(Result::eI2pError, "SAM: " + host + " is not an IPv4 address");
    }
    if ((ntohl(addr.sin_addr.s_addr) >> 24) != kLoopbackFirstOctet) {
        throw Error(Result::eI2pError, "SAM: " + host + " is not a loopback address");
    }
    return addr;
}

Socket openControlSocket(const std::string& host, const std::uint16_t port)
{
    const sockaddr_in addr = loopbackAddress(host, port);
    ensureSockets();
    Held fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no socket");
    }
    quietenSignals(fd.get());
    if (::connect(native(fd.get()), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw Error(Result::eI2pError,
            "SAM: no router at " + host + ":" + std::to_string(port));
    }
    setSocketTimeouts(fd.get(), kControlIoTimeoutSeconds);
    return fd.release();
}

Socket openLocalUdpSocket(std::uint16_t& boundPort)
{
    ensureSockets();
    Held fd(::socket(AF_INET, SOCK_DGRAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no datagram socket");
    }
    quietenSignals(fd.get());
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(native(fd.get()), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw Error(Result::eI2pError, "SAM: could not bind a datagram socket");
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(native(fd.get()), reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        throw Error(Result::eI2pError, "SAM: could not read the datagram port");
    }
    boundPort = ntohs(bound.sin_port);
    return fd.release();
}

Socket openLocalListener(std::uint16_t& boundPort)
{
    ensureSockets();
    Held fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd.valid()) {
        throw Error(Result::eI2pError, "SAM: no listening socket");
    }
    quietenSignals(fd.get());
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(native(fd.get()), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0
        || ::listen(native(fd.get()), kListenBacklog) != 0) {
        throw Error(Result::eI2pError, "SAM: could not listen for forwarded streams");
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(native(fd.get()), reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        throw Error(Result::eI2pError, "SAM: could not read the listening port");
    }
    boundPort = ntohs(bound.sin_port);
    return fd.release();
}

void writeAllSocket(const Socket socket, const void* data, const std::size_t size)
{
    const auto* cursor = static_cast<const unsigned char*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const std::ptrdiff_t written = socketWrite(socket, cursor + sent, size - sent);
        if (written <= 0) {
            throw Error(Result::eI2pError, "SAM: the connection went away while writing");
        }
        sent += static_cast<std::size_t>(written);
    }
}

std::string readLineSocket(const Socket socket)
{
    std::string line;
    while (true) {
        char c = 0;
        const std::ptrdiff_t got = socketRead(socket, &c, 1);
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

std::map<std::string, std::string> commandSocket(
    const Socket socket, const std::string& line, const std::string& expectedPrefix)
{
    writeAllSocket(socket, line.data(), line.size());
    const std::string reply = readLineSocket(socket);
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

std::string handshake(const Socket socket)
{
    const std::map<std::string, std::string> reply
        = commandSocket(socket, "HELLO VERSION MIN=3.1 MAX=3.3\n", "HELLO REPLY");
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

// The tunnel profile as I2CP options.
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
         << " SIGNATURE_TYPE=" << kEd25519SignatureType
         << " i2cp.leaseSetType=" << kEncryptedLeaseSetType;
    if (!config.published) {
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

bool waitReadable(const Socket socket, const int timeoutMs)
{
    return socketReadable(socket, timeoutMs);
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
    const Held control(openControlSocket(router.host, router.controlPort));
    return handshake(control.get());
}

Destination generateDestination(const RouterAddress& router)
{
    const Held control(openControlSocket(router.host, router.controlPort));
    (void)handshake(control.get());
    const std::map<std::string, std::string> reply = commandSocket(control.get(),
        "DEST GENERATE SIGNATURE_TYPE=" + std::to_string(kEd25519SignatureType) + "\n",
        "DEST REPLY");
    const auto pub = reply.find("PUB");
    const auto priv = reply.find("PRIV");
    if (pub == reply.end() || priv == reply.end()) {
        throw Error(Result::eUnknown, "SAM: DEST REPLY carried no keys");
    }
    return Destination{pub->second, priv->second};
}

Stream::Stream(const Socket socket)
    : socket_(socket)
{
}

Stream::~Stream()
{
    close();
}

void Stream::setReadTimeout(const int seconds)
{
    readTimeoutSeconds_ = seconds;
}

std::size_t Stream::readSome(void* buffer, const std::size_t size)
{
    if (socket_ == kInvalidSocket) {
        return 0;
    }
    if (readTimeoutSeconds_ > 0
        && !socketReadable(socket_, readTimeoutSeconds_ * kMillisecondsPerSecond)) {
        throw Error(Result::eI2pError,
            "SAM: nothing read within " + std::to_string(readTimeoutSeconds_) + "s");
    }
    const std::ptrdiff_t got = socketRead(socket_, buffer, size);
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
    if (socket_ == kInvalidSocket) {
        throw Error(Result::eI2pError, "SAM: write to a closed stream");
    }
    writeAllSocket(socket_, data, size);
}

std::size_t Stream::pendingBytes() const
{
    if (socket_ == kInvalidSocket) {
        return 0;
    }
    return socketSendQueue(socket_);
}

void Stream::close()
{
    if (socket_ != kInvalidSocket) {
        closeSocket(socket_);
        socket_ = kInvalidSocket;
    }
}

struct Session::Impl {
    RouterAddress router;
    SessionConfig config;
    std::chrono::seconds readyTimeout{0};
    std::string id;
    std::string publicDestination;
    std::string privateKeys;

    mutable std::mutex mutex;
    mutable std::mutex listenMutex;
    Held control;
    Held forward;
    Held listener;
    Held datagrams;
    std::uint16_t listenPort = 0;
    std::uint16_t datagramPort = 0;
    std::atomic<bool> listening{false};
    std::atomic<bool> alive{false};

    std::atomic<bool> stopping{false};
    std::thread watch;

    void create()
    {
        Held control(openControlSocket(router.host, router.controlPort));
        (void)handshake(control.get());
        setSocketTimeouts(control.get(), static_cast<int>(readyTimeout.count()));
        const std::map<std::string, std::string> created = commandSocket(control.get(),
            sessionCreateLine(id, config, datagramPort), "SESSION STATUS");
        setSocketTimeouts(control.get(), kControlIoTimeoutSeconds);
        const auto keys = created.find("DESTINATION");
        if (keys == created.end()) {
            throw Error(Result::eUnknown, "SAM: SESSION STATUS carried no destination");
        }
        const std::map<std::string, std::string> naming
            = commandSocket(control.get(), "NAMING LOOKUP NAME=ME\n", "NAMING REPLY");
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

    void startForwarding()
    {
        Held forwarder(openControlSocket(router.host, router.controlPort));
        (void)handshake(forwarder.get());
        (void)commandSocket(forwarder.get(),
            "STREAM FORWARD ID=" + id + " PORT=" + std::to_string(listenPort) + " HOST="
                + kDefaultHost + " SILENT=false\n",
            "STREAM STATUS");
        const std::lock_guard<std::mutex> lock(mutex);
        forward.reset(forwarder.release());
    }

    void watchLoop()
    {
        while (!stopping) {
            Socket fd = kInvalidSocket;
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
            const std::ptrdiff_t got = peekByte(fd);
            if (got > 0) {
                continue;
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
                    config.privateKeys = privateKeys;
                }
                create();
                {
                    const std::lock_guard<std::mutex> lock(listenMutex);
                    if (listening) {
                        startForwarding();
                    }
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
    return i2p::routingHost(impl_->publicDestination);
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
    Held stream(openControlSocket(impl_->router.host, impl_->router.controlPort));
    (void)handshake(stream.get());
    setSocketTimeouts(stream.get(), static_cast<int>(timeout.count()));
    (void)commandSocket(stream.get(),
        "STREAM CONNECT ID=" + impl_->id + " DESTINATION=" + destination + " SILENT=false\n",
        "STREAM STATUS");
    setSocketTimeouts(stream.get(), 0);
    return std::make_unique<Stream>(stream.release());
}

void Session::listen()
{
    const std::lock_guard<std::mutex> lock(impl_->listenMutex);
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
    Held incoming(::accept(native(impl_->listener.get()), nullptr, nullptr));
    if (!incoming.valid()) {
        throw Error(Result::eI2pError, "SAM: could not take a forwarded stream");
    }
    // An accepted socket does not inherit this from the one that listened.
    quietenSignals(incoming.get());
    setSocketTimeouts(incoming.get(), kControlIoTimeoutSeconds);
    const std::string peerLine = readLineSocket(incoming.get());
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
    const std::ptrdiff_t sent
        = socketSendTo(impl_->datagrams.get(), packet.data(), packet.size(), addr);
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
    const std::ptrdiff_t got
        = socketRead(impl_->datagrams.get(), buffer.data(), buffer.size());
    if (got <= 0) {
        return {};
    }
    buffer.resize(static_cast<std::size_t>(got));
    if (impl_->config.style == Style::eRaw) {
        return buffer;
    }
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
