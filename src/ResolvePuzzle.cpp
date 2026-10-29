// Bazarish project (c) 2026
#include "bazarish/ResolvePuzzle.hpp"

#include <atomic>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace bazarish {

namespace {

constexpr unsigned kBitsPerByte = 8;

Bytes nonceBytes(std::uint64_t nonce)
{
    Bytes out(sizeof nonce);
    for (std::size_t i = out.size(); i > 0; --i) {
        out[i - 1] = static_cast<unsigned char>(nonce & 0xff);
        nonce >>= kBitsPerByte;
    }
    return out;
}

bool startsWithZeroBits(const Bytes& digest, const std::uint32_t bits)
{
    std::uint32_t left = bits;
    for (const unsigned char byte : digest) {
        if (left == 0) {
            return true;
        }
        if (left >= kBitsPerByte) {
            if (byte != 0) {
                return false;
            }
            left -= kBitsPerByte;
            continue;
        }
        return (byte >> (kBitsPerByte - left)) == 0;
    }
    return left == 0;
}

}  // namespace

bool puzzleSolved(const Bytes& stamp, const std::uint64_t nonce, const std::uint32_t bits)
{
    if (bits > kMaxPuzzleBits) {
        throw std::invalid_argument("a puzzle harder than the protocol allows");
    }
    return startsWithZeroBits(argon2id(nonceBytes(nonce), stamp, kPuzzleCost, kPuzzleDigestBytes), bits);
}

std::uint64_t solvePuzzle(const Bytes& stamp, const std::uint32_t bits, const unsigned threads)
{
    if (bits > kMaxPuzzleBits) {
        throw std::invalid_argument("a puzzle harder than the protocol allows");
    }
    const unsigned workers = threads == 0 ? 1 : threads;
    std::atomic<bool> found{false};
    std::uint64_t answer = 0;
    std::exception_ptr failure;
    std::mutex guard;
    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (unsigned worker = 0; worker < workers; ++worker) {
        pool.emplace_back([&, worker]() {
            try {
                for (std::uint64_t nonce = worker; !found.load(); nonce += workers) {
                    if (puzzleSolved(stamp, nonce, bits)) {
                        const std::lock_guard<std::mutex> lock(guard);
                        if (!found.exchange(true)) {
                            answer = nonce;
                        }
                    }
                }
            } catch (const std::exception&) {
                // error-hiding: allowed - rethrown once the workers have joined
                const std::lock_guard<std::mutex> lock(guard);
                failure = std::current_exception();
                found.store(true);
            }
        });
    }
    for (std::thread& thread : pool) {
        thread.join();
    }
    if (failure) {
        std::rethrow_exception(failure);
    }
    return answer;
}

}  // namespace bazarish
