// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>

namespace bazarish {

// Key material that is wiped before its memory is given back: on destruction, on assignment and on clear().
class SecretBytes {
public:
    SecretBytes() = default;
    explicit SecretBytes(Bytes bytes);
    explicit SecretBytes(std::size_t size);
    SecretBytes(const SecretBytes& other);
    SecretBytes(SecretBytes&& other) noexcept;
    SecretBytes& operator=(const SecretBytes& other);
    SecretBytes& operator=(SecretBytes&& other) noexcept;
    ~SecretBytes();

    const Bytes& bytes() const;
    unsigned char* data();
    std::size_t size() const;
    bool empty() const;
    void resize(std::size_t size);
    // Overwrites the content with zeros and keeps its size.
    void wipe();
    void clear();
    // Hands the bytes on unwiped, for a value whose owner takes over keeping it.
    Bytes release();

    bool operator==(const SecretBytes& other) const;

private:
    Bytes bytes_;
};

}  // namespace bazarish
