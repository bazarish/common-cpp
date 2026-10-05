// Bazarish project (c) 2026
#include "bazarish/GatewayStreamBook.hpp"

#include "TestUtil.hpp"

#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

void write(StreamBook& book, const std::string& text)
{
    book.wrote(text.data(), text.size());
}

std::string text(const Bytes& bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

}  // namespace

int main()
{
    StreamBook book;
    CHECK(book.room() == kStreamWindowBytes);
    CHECK(book.sent() == 0);
    CHECK(book.pending() == 0);
    CHECK(!book.finishedSending());
    CHECK(!book.peerHasFinished());

    write(book, "alpha");
    write(book, "beta");
    CHECK(book.sent() == 9);
    CHECK(book.pending() == 9);
    CHECK(book.room() == kStreamWindowBytes - 9);

    book.peerCredited(5);
    CHECK(book.credited() == 5);
    CHECK(book.pending() == 4);
    book.peerCredited(5);
    CHECK(book.credited() == 5);
    book.peerCredited(4);
    CHECK(book.credited() == 5);
    CHECK_THROWS(book.peerCredited(book.sent() + 1));

    CHECK(text(book.replay(5)) == "beta");
    CHECK(text(book.replay(5)) == "beta");
    CHECK(text(book.replay(7)) == "ta");
    CHECK(text(book.replay(9)).empty());
    CHECK_THROWS(book.replay(8));
    CHECK_THROWS(book.replay(book.sent() + 1));

    StreamBook fed;
    write(fed, "alphabeta");
    fed.peerCredited(5);
    CHECK_THROWS(fed.replay(4));
    CHECK(text(fed.replay(5)) == "beta");

    StreamBook bulk;
    const std::string chunk(1024, 'x');
    for (int i = 0; i < 16; ++i) {
        bulk.wrote(chunk.data(), chunk.size());
    }
    CHECK(bulk.sent() == 16 * 1024);
    bulk.peerCredited(16 * 1024);
    CHECK(bulk.pending() == 0);
    CHECK(bulk.room() == kStreamWindowBytes);
    CHECK(bulk.replay(16 * 1024).empty());

    StreamBook tight;
    const std::string wholeWindow(kStreamWindowBytes, 'y');
    tight.wrote(wholeWindow.data(), wholeWindow.size());
    CHECK(tight.room() == 0);
    CHECK_THROWS(tight.wrote(chunk.data(), 1));
    tight.peerCredited(1);
    CHECK(tight.room() == 1);
    tight.wrote(chunk.data(), 1);
    CHECK(tight.room() == 0);

    StreamBook inbound;
    inbound.tookIn(kStreamWindowBytes);
    CHECK(inbound.received() == kStreamWindowBytes);
    CHECK_THROWS(inbound.tookIn(1));
    inbound.consumed(kStreamWindowBytes);
    CHECK(inbound.consumedTotal() == kStreamWindowBytes);
    inbound.tookIn(1);
    CHECK_THROWS(inbound.consumed(2));

    StreamBook ending;
    ending.finishSending();
    CHECK(ending.finishedSending());
    CHECK(!ending.peerHasFinished());
    ending.peerFinished();
    CHECK(ending.peerHasFinished());

    std::printf("TestGatewayStreamBook ok\n");
    return 0;
}
