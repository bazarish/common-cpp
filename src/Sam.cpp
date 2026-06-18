// Bazarish project (c) 2026
#include "bazarish/Sam.hpp"

#include "bazarish/I2pAddress.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <sstream>
#include <stdexcept>
#include <utility>

namespace {

// EdDSA-SHA512-Ed25519 per the I2P common structures spec.
constexpr int kEd25519SignatureType = 7;

// I2P tunnel construction and stream setup are slow; this bound only stops
// a wedged router from hanging a caller forever, it is not a latency target.
constexpr int kSamSocketTimeoutSeconds = 240;

// Splits a SAM reply line into key=value pairs after the two reply words.
// SAM values containing spaces are quoted; quotes are stripped.
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
            const std::size_t eq = line.find('=', pos);
            if (eq == std::string::npos) {
                break;
            }
            const std::string key = line.substr(pos, eq - pos);
            std::string value;
            std::size_t cursor = eq + 1;
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
        std::size_t end = pos;
        while (end < line.size() && line[end] != ' ') {
            ++end;
        }
        pos = end;
        ++word;
    }
    return values;
}

bool hasReplyPrefix(const std::string& line, const std::string& prefix)
{
    return line.size() >= prefix.size() && line.compare(0, prefix.size(), prefix) == 0;
}

int openSamSocket(const std::string& host, const std::uint16_t port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("socket creation failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        throw std::invalid_argument("invalid SAM host address");
    }
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        throw std::runtime_error("SAM connection failed");
    }
    timeval timeout{};
    timeout.tv_sec = kSamSocketTimeoutSeconds;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

void writeAllFd(const int fd, const void* data, const std::size_t size)
{
    const auto* cursor = static_cast<const unsigned char*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const ssize_t written = ::write(fd, cursor + sent, size - sent);
        if (written <= 0) {
            throw std::runtime_error("socket write failed");
        }
        sent += static_cast<std::size_t>(written);
    }
}

std::string readLineFd(const int fd)
{
    std::string line;
    char c = 0;
    while (true) {
        const ssize_t got = ::read(fd, &c, 1);
        if (got <= 0) {
            throw std::runtime_error("socket read failed");
        }
        if (c == '\n') {
            break;
        }
        line.push_back(c);
    }
    return line;
}

// Sends a command line and parses the reply, verifying the prefix and that
// RESULT, if present, is OK.
std::map<std::string, std::string> commandFd(
    const int fd, const std::string& line, const std::string& expectedReplyPrefix)
{
    writeAllFd(fd, line.data(), line.size());
    const std::string reply = readLineFd(fd);
    if (!hasReplyPrefix(reply, expectedReplyPrefix)) {
        throw std::runtime_error("unexpected SAM reply: " + reply);
    }
    std::map<std::string, std::string> values = parseReply(reply);
    const auto result = values.find("RESULT");
    if (result != values.end() && result->second != "OK") {
        throw std::runtime_error("SAM command failed: " + reply);
    }
    return values;
}

void handshakeFd(const int fd)
{
    const std::map<std::string, std::string> reply
        = commandFd(fd, "HELLO VERSION MIN=3.1 MAX=3.3\n", "HELLO REPLY");
    if (reply.find("VERSION") == reply.end()) {
        throw std::runtime_error("SAM HELLO reply has no VERSION");
    }
}

}  // namespace

namespace bazarish {

SamStream::SamStream(const int fd)
    : fd_(fd)
{
}

SamStream::~SamStream()
{
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

SamStream::SamStream(SamStream&& other) noexcept
    : fd_(other.fd_)
{
    other.fd_ = -1;
}

SamStream& SamStream::operator=(SamStream&& other) noexcept
{
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

std::size_t SamStream::readSome(void* buffer, const std::size_t size)
{
    const ssize_t got = ::read(fd_, buffer, size);
    if (got < 0) {
        throw std::runtime_error("stream read failed");
    }
    return static_cast<std::size_t>(got);
}

void SamStream::readExact(void* buffer, const std::size_t size)
{
    auto* cursor = static_cast<unsigned char*>(buffer);
    std::size_t total = 0;
    while (total < size) {
        const std::size_t got = readSome(cursor + total, size - total);
        if (got == 0) {
            throw std::runtime_error("stream closed before readExact completed");
        }
        total += got;
    }
}

void SamStream::writeAll(const void* data, const std::size_t size)
{
    writeAllFd(fd_, data, size);
}

void SamStream::shutdownWrite()
{
    ::shutdown(fd_, SHUT_WR);
}

int SamStream::fd() const
{
    return fd_;
}

SamClient::SamClient(const std::string& host, const std::uint16_t port)
    : fd_(-1)
{
    fd_ = openSamSocket(host, port);
    try {
        const std::map<std::string, std::string> reply
            = commandFd(fd_, "HELLO VERSION MIN=3.1 MAX=3.3\n", "HELLO REPLY");
        const auto version = reply.find("VERSION");
        if (version == reply.end()) {
            throw std::runtime_error("SAM HELLO reply has no VERSION");
        }
        version_ = version->second;
    } catch (...) {
        ::close(fd_);
        fd_ = -1;
        throw;
    }
}

SamClient::~SamClient()
{
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

const std::string& SamClient::version() const
{
    return version_;
}

SamClient::Destination SamClient::generateDestination()
{
    std::ostringstream request;
    request << "DEST GENERATE SIGNATURE_TYPE=" << kEd25519SignatureType << "\n";
    const std::map<std::string, std::string> reply = command(request.str(), "DEST REPLY");
    const auto pub = reply.find("PUB");
    const auto priv = reply.find("PRIV");
    if (pub == reply.end() || priv == reply.end()) {
        throw std::runtime_error("SAM DEST reply is missing keys");
    }
    return Destination{pub->second, priv->second};
}

std::map<std::string, std::string> SamClient::command(
    const std::string& line, const std::string& expectedReplyPrefix)
{
    return commandFd(fd_, line, expectedReplyPrefix);
}

std::string SamClient::readLine()
{
    return readLineFd(fd_);
}

std::string i2pPrivacyOptions(const I2pPrivacy privacy)
{
    switch (privacy) {
    case I2pPrivacy::eMinimal:
        return "inbound.length=1 outbound.length=1";
    case I2pPrivacy::eMiddle:
        return "inbound.length=1 outbound.length=1 "
               "inbound.lengthVariance=1 outbound.lengthVariance=1";
    case I2pPrivacy::eMax:
        return "inbound.length=2 outbound.length=2 "
               "inbound.lengthVariance=1 outbound.lengthVariance=1";
    }
    return "";
}

std::optional<I2pPrivacy> i2pPrivacyFromString(const std::string& text)
{
    if (text == "minimal") {
        return I2pPrivacy::eMinimal;
    }
    if (text == "middle") {
        return I2pPrivacy::eMiddle;
    }
    if (text == "max") {
        return I2pPrivacy::eMax;
    }
    return std::nullopt;
}

std::string i2pTunnelQuantityOptions(int quantity)
{
    if (quantity < 1) {
        quantity = 1;
    }
    if (quantity > kMaxTunnelQuantity) {
        quantity = kMaxTunnelQuantity;
    }
    const std::string n = std::to_string(quantity);
    return "inbound.quantity=" + n + " outbound.quantity=" + n;
}

SamSession::SamSession(const std::string& host, const std::uint16_t port,
    const std::string& sessionId, const std::string& privateKeys, const int leaseSetType,
    const I2pPrivacy privacy, const int tunnelQuantity)
    : host_(host)
    , port_(port)
    , sessionId_(sessionId)
    , leaseSetType_(leaseSetType)
    , controlFd_(-1)
{
    controlFd_ = openSamSocket(host, port);
    try {
        handshakeFd(controlFd_);
        std::ostringstream create;
        create << "SESSION CREATE STYLE=STREAM ID=" << sessionId_ << " DESTINATION="
               << privateKeys << " SIGNATURE_TYPE=" << kEd25519SignatureType
               << " i2cp.leaseSetType=" << leaseSetType << " " << i2pPrivacyOptions(privacy)
               << " " << i2pTunnelQuantityOptions(tunnelQuantity) << "\n";
        const std::map<std::string, std::string> created
            = commandFd(controlFd_, create.str(), "SESSION STATUS");
        const auto destination = created.find("DESTINATION");
        if (destination != created.end()) {
            privateDestination_ = destination->second;
        }

        // The session destination is the private blob; NAMING LOOKUP ME
        // returns our shareable public destination.
        const std::map<std::string, std::string> naming
            = commandFd(controlFd_, "NAMING LOOKUP NAME=ME\n", "NAMING REPLY");
        const auto value = naming.find("VALUE");
        if (value == naming.end()) {
            throw std::runtime_error("SAM NAMING reply has no VALUE");
        }
        publicDestination_ = value->second;
    } catch (...) {
        ::close(controlFd_);
        controlFd_ = -1;
        throw;
    }
}

SamSession::~SamSession()
{
    if (controlFd_ >= 0) {
        ::close(controlFd_);
    }
}

const std::string& SamSession::publicDestination() const
{
    return publicDestination_;
}

std::string SamSession::routingAddress() const
{
    // Every routing target is a full .b32.i2p host (project-wide invariant): an
    // encrypted LeaseSet2 is reached via its blinded b33, a standard LeaseSet2
    // (e.g. an offline-key destination, which cannot publish a b33) via its
    // standard b32. The raw destination is never used as an address.
    if (leaseSetType_ == kEncryptedLeaseSetType) {
        return encryptedLeaseSetHost(publicDestination_);
    }
    return standardLeaseSetHost(publicDestination_);
}

const std::string& SamSession::privateDestination() const
{
    return privateDestination_;
}

const std::string& SamSession::sessionId() const
{
    return sessionId_;
}

SamStream SamSession::connect(const std::string& destination)
{
    const int fd = openSamSocket(host_, port_);
    try {
        handshakeFd(fd);
        commandFd(fd, "STREAM CONNECT ID=" + sessionId_ + " DESTINATION=" + destination
                + " SILENT=false\n",
            "STREAM STATUS");
    } catch (...) {
        ::close(fd);
        throw;
    }
    return SamStream(fd);
}

SamStream SamSession::accept(std::string& peerDestination)
{
    const int fd = openSamSocket(host_, port_);
    try {
        handshakeFd(fd);
        commandFd(fd, "STREAM ACCEPT ID=" + sessionId_ + " SILENT=false\n", "STREAM STATUS");
        // With SILENT=false the first line after a peer connects is its
        // base64 destination (followed by optional options).
        const std::string peerLine = readLineFd(fd);
        peerDestination = peerLine.substr(0, peerLine.find(' '));
    } catch (...) {
        ::close(fd);
        throw;
    }
    return SamStream(fd);
}

}  // namespace bazarish
