// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <cstddef>
#include <exception>

namespace bazarish::client {

// Tells a stream that failed under an exchange from an answer that does not read.
template <class Stream>
class BasicWatchedStream {
public:
    explicit BasicWatchedStream(Stream& stream) : stream_(stream) {}

    std::size_t readSome(const ByteBuffer buffer)
    {
        try {
            const std::size_t got = stream_.readSome(buffer);
            ended_ = ended_ || got == 0;
            return got;
        } catch (const std::exception&) {
            broke_ = true;
            throw;
        }
    }

    void writeAll(const ByteView data)
    {
        try {
            stream_.writeAll(data);
        } catch (const std::exception&) {
            broke_ = true;
            throw;
        }
    }

    bool failed() const { return ended_ || broke_; }

private:
    Stream& stream_;
    bool ended_ = false;
    bool broke_ = false;
};

using WatchedStream = BasicWatchedStream<bazarish::i2p::Stream>;

}  // namespace bazarish::client
