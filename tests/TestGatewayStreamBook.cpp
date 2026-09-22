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
    // A stream starts with a whole window and nothing owed.
    StreamBook book;
    CHECK(book.room() == kStreamWindowBytes);
    CHECK(book.sent() == 0);
    CHECK(book.pending() == 0);
    CHECK(!book.finishedSending());
    CHECK(!book.peerHasFinished());

    // What is written is outstanding until the peer says it consumed it.
    write(book, "alpha");
    write(book, "beta");
    CHECK(book.sent() == 9);
    CHECK(book.pending() == 9);
    CHECK(book.room() == kStreamWindowBytes - 9);

    // A credit is cumulative: it says the total, not an increment.
    book.peerCredited(5);
    CHECK(book.credited() == 5);
    CHECK(book.pending() == 4);
    book.peerCredited(5);
    CHECK(book.credited() == 5);
    CHECK_THROWS(book.peerCredited(4));
    CHECK_THROWS(book.peerCredited(book.sent() + 1));

    // What the peer has not confirmed receiving goes out again, and what it has
    // is dropped.
    CHECK(text(book.replay(5)) == "beta");
    // Replaying twice with the same count is the same answer, because a resume
    // that happens twice must land in the same place.
    CHECK(text(book.replay(5)) == "beta");
    CHECK(text(book.replay(7)) == "ta");
    CHECK(text(book.replay(9)).empty());
    // Receiving is monotonic. A count below what the peer already confirmed
    // asks for bytes this side has dropped, and it is refused rather than
    // answered with whatever is left.
    CHECK_THROWS(book.replay(8));
    CHECK_THROWS(book.replay(book.sent() + 1));

    // The same refusal when the confirmation came from a credit rather than a
    // previous resume.
    StreamBook fed;
    write(fed, "alphabeta");
    fed.peerCredited(5);
    CHECK_THROWS(fed.replay(4));
    CHECK(text(fed.replay(5)) == "beta");

    // A credit drops what it covers, so the retained bytes are a window and not
    // a transcript of the stream.
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

    // The window is a wall for the writer, not a suggestion.
    StreamBook tight;
    const std::string wholeWindow(kStreamWindowBytes, 'y');
    tight.wrote(wholeWindow.data(), wholeWindow.size());
    CHECK(tight.room() == 0);
    CHECK_THROWS(tight.wrote(chunk.data(), 1));
    tight.peerCredited(1);
    CHECK(tight.room() == 1);
    tight.wrote(chunk.data(), 1);
    CHECK(tight.room() == 0);

    // And a wall for the peer: more than was granted is a protocol violation,
    // not a buffer that quietly grows.
    StreamBook inbound;
    inbound.tookIn(kStreamWindowBytes);
    CHECK(inbound.received() == kStreamWindowBytes);
    CHECK_THROWS(inbound.tookIn(1));
    inbound.consumed(kStreamWindowBytes);
    CHECK(inbound.consumedTotal() == kStreamWindowBytes);
    inbound.tookIn(1);
    CHECK_THROWS(inbound.consumed(2));

    // Finishing is remembered on both sides, because a byte count alone does
    // not carry an end.
    StreamBook ending;
    ending.finishSending();
    CHECK(ending.finishedSending());
    CHECK(!ending.peerHasFinished());
    ending.peerFinished();
    CHECK(ending.peerHasFinished());

    std::printf("TestGatewayStreamBook ok\n");
    return 0;
}
