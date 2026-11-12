// Bazarish project (c) 2026
#pragma once

#include "TlsEngine.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/role.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/websocket/teardown.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <utility>

namespace bazarish::http {

// Never sees the TLS library: no Asio SSL template is instantiated against two libraries.
class ChromeTlsStream {
public:
    using next_layer_type = boost::beast::tcp_stream;
    using executor_type = next_layer_type::executor_type;

    ChromeTlsStream(boost::asio::io_context& loop, std::unique_ptr<TlsEngine> engine)
        : next_(loop)
        , core_(std::make_unique<Core>(next_.get_executor(), std::move(engine)))
    {
    }

    executor_type get_executor() noexcept { return next_.get_executor(); }
    next_layer_type& next_layer() noexcept { return next_; }
    const next_layer_type& next_layer() const noexcept { return next_; }
    const TlsEngine& engine() const { return *core_->engine; }

    template <class Handler>
    auto async_handshake(Handler&& handler)
    {
        return start(Handshake{}, std::forward<Handler>(handler));
    }

    template <class MutableBuffers, class Handler>
    auto async_read_some(const MutableBuffers& buffers, Handler&& handler)
    {
        return start(Read{firstOf<boost::asio::mutable_buffer>(buffers)},
            std::forward<Handler>(handler));
    }

    template <class ConstBuffers, class Handler>
    auto async_write_some(const ConstBuffers& buffers, Handler&& handler)
    {
        return start(Write{firstOf<boost::asio::const_buffer>(buffers)},
            std::forward<Handler>(handler));
    }

private:
    // As much as one TLS record with its overhead.
    static constexpr std::size_t kChunkBytes = 17 * 1024;

    // Reads and writes of the socket each go one at a time; a gate wakes those waiting.
    struct Core {
        Core(const executor_type& executor, std::unique_ptr<TlsEngine> held)
            : engine(std::move(held))
            , readGate(executor)
            , writeGate(executor)
        {
            readGate.expires_at(boost::asio::steady_timer::time_point::max());
            writeGate.expires_at(boost::asio::steady_timer::time_point::max());
        }

        std::unique_ptr<TlsEngine> engine;
        std::array<unsigned char, kChunkBytes> inbox{};
        std::span<const unsigned char> unread;
        std::array<unsigned char, kChunkBytes> outbox{};
        boost::asio::steady_timer readGate;
        boost::asio::steady_timer writeGate;
        bool reading = false;
        bool writing = false;
    };

    struct Handshake {
        TlsWant operator()(TlsEngine& engine, std::size_t& moved) const
        {
            moved = 0;
            return engine.handshake();
        }
    };

    struct Read {
        boost::asio::mutable_buffer into;
        TlsWant operator()(TlsEngine& engine, std::size_t& moved) const
        {
            if (into.size() == 0) {
                moved = 0;
                return TlsWant::eNothing;
            }
            return engine.read(
                std::span<unsigned char>(static_cast<unsigned char*>(into.data()), into.size()),
                moved);
        }
    };

    struct Write {
        boost::asio::const_buffer from;
        TlsWant operator()(TlsEngine& engine, std::size_t& moved) const
        {
            if (from.size() == 0) {
                moved = 0;
                return TlsWant::eNothing;
            }
            return engine.write(std::span<const unsigned char>(
                                    static_cast<const unsigned char*>(from.data()), from.size()),
                moved);
        }
    };

    template <class Buffer, class Buffers>
    static Buffer firstOf(const Buffers& buffers)
    {
        for (auto at = boost::asio::buffer_sequence_begin(buffers);
             at != boost::asio::buffer_sequence_end(buffers); ++at) {
            const Buffer buffer(*at);
            if (buffer.size() > 0) {
                return buffer;
            }
        }
        return Buffer();
    }

    template <class Operation>
    class Op : boost::asio::coroutine {
    public:
        Op(Core& core, next_layer_type& next, Operation operation)
            : core_(core)
            , next_(next)
            , operation_(std::move(operation))
        {
        }

        template <class Self>
        void operator()(Self& self, const boost::system::error_code error = {},
            const std::size_t transferred = 0)
        {
            BOOST_ASIO_CORO_REENTER(*this)
            {
                for (;;) {
                    want_ = operation_(*core_.engine, moved_);
                    if (want_ == TlsWant::eOutput || want_ == TlsWant::eOutputAndRetry) {
                        while (core_.writing) {
                            waited_ = true;
                            BOOST_ASIO_CORO_YIELD core_.writeGate.async_wait(std::move(self));
                        }
                        core_.writing = true;
                        while (!failed_
                            && (pending_ = core_.engine->takeOutput(core_.outbox)) > 0) {
                            waited_ = true;
                            BOOST_ASIO_CORO_YIELD boost::asio::async_write(next_,
                                boost::asio::buffer(core_.outbox.data(), pending_),
                                std::move(self));
                            failed_ = error;
                        }
                        core_.writing = false;
                        core_.writeGate.cancel();
                        if (failed_ || want_ == TlsWant::eOutput) {
                            break;
                        }
                        continue;
                    }
                    if (want_ == TlsWant::eInputAndRetry) {
                        if (!core_.unread.empty()) {
                            const std::size_t given = core_.engine->giveInput(core_.unread);
                            core_.unread = core_.unread.subspan(given);
                            continue;
                        }
                        if (core_.reading) {
                            waited_ = true;
                            BOOST_ASIO_CORO_YIELD core_.readGate.async_wait(std::move(self));
                            continue;
                        }
                        core_.reading = true;
                        waited_ = true;
                        BOOST_ASIO_CORO_YIELD next_.async_read_some(
                            boost::asio::buffer(core_.inbox), std::move(self));
                        core_.reading = false;
                        core_.readGate.cancel();
                        failed_ = error;
                        if (failed_) {
                            break;
                        }
                        core_.unread
                            = std::span<const unsigned char>(core_.inbox).first(transferred);
                        continue;
                    }
                    if (want_ == TlsWant::eClosed) {
                        failed_ = boost::asio::error::eof;
                    }
                    if (want_ == TlsWant::eFailed) {
                        failed_ = boost::system::errc::make_error_code(
                            boost::system::errc::protocol_error);
                    }
                    break;
                }
                // A completion never runs inside the call that started the operation.
                if (!waited_) {
                    BOOST_ASIO_CORO_YIELD boost::asio::post(next_.get_executor(), std::move(self));
                }
                self.complete(failed_, failed_ ? 0 : moved_);
            }
        }

    private:
        Core& core_;
        next_layer_type& next_;
        Operation operation_;
        TlsWant want_ = TlsWant::eNothing;
        std::size_t moved_ = 0;
        std::size_t pending_ = 0;
        bool waited_ = false;
        boost::system::error_code failed_;
    };

    template <class Operation, class Handler>
    auto start(Operation operation, Handler&& handler)
    {
        return boost::asio::async_compose<Handler, void(boost::system::error_code, std::size_t)>(
            Op<Operation>(*core_, next_, std::move(operation)), handler, next_);
    }

    next_layer_type next_;
    std::unique_ptr<Core> core_;
};

// Chrome closes a connection without close_notify; a WebSocket ends at the TCP layer.
inline void teardown(const boost::beast::role_type role, ChromeTlsStream& stream,
    boost::system::error_code& error)
{
    using boost::beast::websocket::teardown;
    teardown(role, stream.next_layer(), error);
}

template <class TeardownHandler>
void async_teardown(
    const boost::beast::role_type role, ChromeTlsStream& stream, TeardownHandler&& handler)
{
    using boost::beast::websocket::async_teardown;
    async_teardown(role, stream.next_layer(), std::forward<TeardownHandler>(handler));
}

}  // namespace bazarish::http
