// Bazarish project (c) 2026
#include "bazarish/Tunnel.hpp"

#include "TestUtil.hpp"

#include <set>
#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;

tunnel::Request sampleRequest()
{
    tunnel::Request request;
    request.method = "POST";
    request.path = "/v1/messaging/ack";
    request.query = "wait=30";
    request.headers = {{"X-Bazarish-Client", "dev-a"}, {"X-Bazarish-Seq", "7"}};
    request.body = Bytes{'{', '}'};
    request.contentType = "application/json";
    return request;
}

}  // namespace

int main()
{
    const Key serverSealing = Key::generateSealing();
    const Identity user = Identity::generate();

    // A hello opens a tunnel: only the server can read it, and what comes out is
    // what went in.
    {
        tunnel::Hello hello;
        hello.secret = randomBytes(32);
        const Key replyKey = Key::generateSealing();
        hello.replyKeyDer = replyKey.publicDer();
        hello.signature = auth::signRequest(user, kNow, tunnel::kHelloMethod, tunnel::kHelloPath,
            hello.secret);

        const Bytes frame = sealHello(hello, Key::fromPublicDer(serverSealing.publicDer()));
        CHECK(tunnel::isHello(frame));
        const tunnel::Hello opened = tunnel::openHello(frame, serverSealing);
        CHECK(opened.secret == hello.secret);
        CHECK(opened.replyKeyDer == hello.replyKeyDer);
        // The signature travelled intact, so the server learns who is opening it
        // - the one and only place an identity is presented.
        CHECK(auth::verifyRequest(opened.signature, kNow, tunnel::kHelloMethod,
                  tunnel::kHelloPath, opened.secret)
            == user.fingerprint());

        // Nobody else opens it.
        const Key stranger = Key::generateSealing();
        CHECK_THROWS(tunnel::openHello(frame, stranger));
        // And it is not a carried frame, so it can never be opened with a tunnel
        // key: a tunnel cannot open the next tunnel.
        CHECK_THROWS(tunnel::open(frame, randomBytes(kAeadKeyBytes)));
        CHECK_THROWS(tunnel::handleOf(frame));

        // The answer comes back sealed to the one-time key from inside the hello.
        const Bytes welcome
            = tunnel::sealWelcome({kNow + 3600}, Key::fromPublicDer(opened.replyKeyDer));
        CHECK(tunnel::openWelcome(welcome, replyKey).expiresUnix == kNow + 3600);
        CHECK_THROWS(tunnel::openWelcome(welcome, stranger));
    }

    // Carried frames: addressed by a handle anybody can read, opened only with
    // the key.
    {
        const Bytes secret = randomBytes(32);
        const std::string sessionId = toHex(sha256(secret)).substr(0, 32);
        const Bytes key = tunnel::deriveTunnelKey(secret, sessionId);
        // The tunnel key is not the MAC key of the same session: one secret, two
        // purposes, and holding one must not hand over the other.
        CHECK(key != auth::deriveSessionKey(secret, sessionId));
        CHECK(key.size() == kAeadKeyBytes);
        CHECK(tunnel::deriveTunnelKey(secret, sessionId) == key);
        CHECK(tunnel::deriveTunnelKey(randomBytes(32), sessionId) != key);

        const Bytes payload = tunnel::encodeRequest(sampleRequest());
        const std::string handle = auth::sessionHandle(secret, 1);
        const Bytes frame = tunnel::carry(handle, key, payload);
        CHECK(!tunnel::isHello(frame));
        CHECK(tunnel::handleOf(frame) == handle);
        CHECK(tunnel::open(frame, key) == payload);

        // A wrong key, and anything changed on the way, are the same answer.
        CHECK_THROWS(tunnel::open(frame, randomBytes(kAeadKeyBytes)));
        {
            Bytes tampered = frame;
            tampered[tampered.size() - 1] ^= 0x01;
            CHECK_THROWS(tunnel::open(tampered, key));
        }
        {
            const Bytes truncated(frame.begin(), frame.end() - 8);
            CHECK_THROWS(tunnel::open(truncated, key));
        }
        // Two frames of the same payload differ: the nonce is fresh each time, so
        // a facade cannot even tell a repeat from a new request.
        CHECK(tunnel::carry(handle, key, payload) != frame);

        // The round trip is exact.
        const tunnel::Request back = tunnel::decodeRequest(tunnel::open(frame, key));
        const tunnel::Request sent = sampleRequest();
        CHECK(back.method == sent.method);
        CHECK(back.path == sent.path);
        CHECK(back.query == sent.query);
        CHECK(back.headers == sent.headers);
        CHECK(back.body == sent.body);
        CHECK(back.contentType == sent.contentType);

        const tunnel::Response answer{403, "application/json", Bytes{'n', 'o'}};
        const tunnel::Response answerBack
            = tunnel::decodeResponse(tunnel::encodeResponse(answer));
        CHECK(answerBack.status == 403);
        CHECK(answerBack.contentType == answer.contentType);
        CHECK(answerBack.body == answer.body);
    }

    // Padding: what the facade measures is the step, not the content. Without
    // this a list of waiting mail still counts itself out loud.
    {
        const Bytes secret = randomBytes(32);
        const Bytes key = tunnel::deriveTunnelKey(secret, "0123456789abcdef0123456789abcdef");
        const std::string handle = auth::sessionHandle(secret, 1);
        std::set<std::size_t> sizes;
        for (const std::size_t bodyLength : {std::size_t{0}, std::size_t{1}, std::size_t{50}}) {
            tunnel::Request request = sampleRequest();
            request.body = Bytes(bodyLength, 'x');
            sizes.insert(tunnel::carry(handle, key, tunnel::encodeRequest(request)).size());
        }
        CHECK(sizes.size() == 1);  // all three weigh the same on the wire

        // A payload past the ladder still lands on a whole step rather than on
        // its own length.
        tunnel::Request large = sampleRequest();
        large.body = Bytes(40000, 'x');
        const std::size_t first = tunnel::carry(handle, key, tunnel::encodeRequest(large)).size();
        large.body = Bytes(40100, 'x');
        CHECK(tunnel::carry(handle, key, tunnel::encodeRequest(large)).size() == first);
    }

    // A frame that is not a frame is refused rather than half-read.
    {
        CHECK(!tunnel::isHello(Bytes{'n', 'o', 't', ' ', 'c', 'b', 'o', 'r'}));
        CHECK_THROWS(tunnel::handleOf(Bytes{'n', 'o', 't'}));
        CHECK_THROWS(tunnel::open(Bytes{}, randomBytes(kAeadKeyBytes)));
    }

    return 0;
}
