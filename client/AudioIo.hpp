// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <vector>

namespace bazarish {

class AudioSource {
public:
    virtual ~AudioSource() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::vector<std::int16_t> readFrame() = 0;
};

class AudioSink {
public:
    virtual ~AudioSink() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void writeFrame(const std::vector<std::int16_t>& pcm) = 0;
};

}  // namespace bazarish
