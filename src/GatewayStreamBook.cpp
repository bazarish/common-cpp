// Bazarish project (c) 2026
#include "bazarish/GatewayStreamBook.hpp"

namespace bazarish::gateway {

std::size_t StreamBook::room() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::uint64_t outstanding = sent_ - credited_;
    return outstanding >= kStreamWindowBytes ? 0
                                             : kStreamWindowBytes
            - static_cast<std::size_t>(outstanding);
}

void StreamBook::wrote(const void* const data, const std::size_t size)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::uint64_t outstanding = sent_ - credited_;
    const std::size_t free = outstanding >= kStreamWindowBytes
        ? 0
        : kStreamWindowBytes - static_cast<std::size_t>(outstanding);
    if (size > free) {
        throw ProtocolError(Fault::eInternal, "a write past the window this stream was granted");
    }
    if (size > 0) {
        const unsigned char* const at = static_cast<const unsigned char*>(data);
        retained_.insert(retained_.end(), at, at + size);
    }
    sent_ += size;
}

void StreamBook::peerCredited(const std::uint64_t total)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (total < credited_) {
        throw ProtocolError(Fault::eBadFrame, "a credit that says less than the last one");
    }
    if (total > sent_) {
        throw ProtocolError(Fault::eBadFrame, "a credit for bytes that were never sent");
    }
    credited_ = total;
    // Consumed means received, so nothing below a credit can still need
    // replaying.
    if (credited_ > retainedFrom_) {
        const std::size_t drop = static_cast<std::size_t>(credited_ - retainedFrom_);
        retained_.erase(retained_.begin(), retained_.begin() + static_cast<std::ptrdiff_t>(drop));
        retainedFrom_ = credited_;
    }
}

Bytes StreamBook::replay(const std::uint64_t peerReceived)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    // Receiving is monotonic: a peer cannot un-receive. Saying less than it
    // already confirmed is not a resume, it is a request to replay bytes this
    // side has thrown away, and answering it with the empty buffer that happens
    // to be left would lose them quietly.
    if (peerReceived < retainedFrom_) {
        throw ProtocolError(
            Fault::eBadFrame, "a peer that received less than it already confirmed");
    }
    if (peerReceived > sent_) {
        throw ProtocolError(Fault::eBadFrame, "a peer that received more than was ever sent");
    }
    if (peerReceived > retainedFrom_) {
        const std::size_t drop = static_cast<std::size_t>(peerReceived - retainedFrom_);
        retained_.erase(retained_.begin(), retained_.begin() + static_cast<std::ptrdiff_t>(drop));
        retainedFrom_ = peerReceived;
    }
    return retained_;
}

void StreamBook::tookIn(const std::size_t size)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (received_ + size - consumed_ > kStreamWindowBytes) {
        throw ProtocolError(Fault::eBadFrame, "more bytes than the window this stream granted");
    }
    received_ += size;
}

void StreamBook::consumed(const std::size_t size)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (consumed_ + size > received_) {
        throw ProtocolError(Fault::eInternal, "more bytes read than ever arrived");
    }
    consumed_ += size;
}

}  // namespace bazarish::gateway
