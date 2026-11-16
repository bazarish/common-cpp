// Bazarish project (c) 2026
#include "bazarish/Tunnel.hpp"

#include "TestUtil.hpp"

#include <set>
#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;
constexpr bazarish::tunnel::Direction kAsked = bazarish::tunnel::Direction::eRequest;

tunnel::Request sampleRequest()
{
    tunnel::Request request;
    request.method = "POST";
    request.path = "/v1/messaging/ack";
    request.query = "wait=30";
    request.headers = {{"X-Bazarish-Client", "dev-a"}, {"X-Bazarish-Seq", "7"}};
    request.body = SecretBytes(Bytes{'{', '}'});
    request.contentType = "application/json";
    return request;
}

}  // namespace

int main()
try {
    const Key serverSealing = Key::generateSealing();
    const Identity user = Identity::generate();

    {
        tunnel::Hello hello;
        hello.secret = SecretBytes(randomBytes(32));
        const Key replyKey = Key::generateSealing();
        hello.replyKeyDer = replyKey.publicDer();
        const std::string server = Identity::generate().fingerprint();
        hello.signature = auth::signRequest(user, kNow, tunnel::kHelloMethod, tunnel::kHelloPath,
            tunnel::helloSigned(hello.secret, server).bytes());

        const Bytes frame = sealHello(hello, Key::fromPublicDer(serverSealing.publicDer()));
        CHECK(tunnel::isHello(frame));
        const tunnel::Hello opened = tunnel::openHello(frame, serverSealing);
        CHECK(opened.secret == hello.secret);
        CHECK(opened.replyKeyDer == hello.replyKeyDer);
        CHECK(auth::verifyRequest(opened.signature, kNow, tunnel::kHelloMethod,
                  tunnel::kHelloPath, tunnel::helloSigned(opened.secret, server).bytes())
            == user.fingerprint());
        CHECK_THROWS(auth::verifyRequest(opened.signature, kNow, tunnel::kHelloMethod,
            tunnel::kHelloPath, tunnel::helloSigned(opened.secret, Identity::generate().fingerprint()).bytes()));
        CHECK_THROWS(tunnel::helloSigned(opened.secret, ""));

        const Key stranger = Key::generateSealing();
        CHECK_THROWS(tunnel::openHello(frame, stranger));
        CHECK_THROWS(tunnel::open(frame, SecretBytes(randomBytes(kAeadKeyBytes)), tunnel::Direction::eRequest, "h"));
        CHECK_THROWS(tunnel::handleOf(frame));

        const Bytes welcome
            = tunnel::sealWelcome({kNow + 3600}, Key::fromPublicDer(opened.replyKeyDer));
        CHECK(tunnel::openWelcome(welcome, replyKey).expiresUnix == kNow + 3600);
        CHECK_THROWS(tunnel::openWelcome(welcome, stranger));
    }

    {
        const SecretBytes secret(randomBytes(32));
        const std::string sessionId = toHex(sha256(secret.bytes())).substr(0, 32);
        const SecretBytes key = tunnel::deriveTunnelKey(secret, sessionId);
        CHECK(!(key == auth::deriveSessionKey(secret, sessionId)));
        const std::string material = toHex(secret.bytes()) + "|" + sessionId + "|bazarish tunnel v1";
        CHECK(key.bytes() == sha256(Bytes(material.begin(), material.end())));
        CHECK(key.size() == kAeadKeyBytes);
        CHECK(tunnel::deriveTunnelKey(secret, sessionId) == key);
        CHECK(!(tunnel::deriveTunnelKey(SecretBytes(randomBytes(32)), sessionId) == key));

        const SecretBytes payload = tunnel::encodeRequest(sampleRequest());
        const std::string handle = auth::sessionHandle(secret, 1);
        const Bytes frame = tunnel::carry(handle, key, kAsked, payload);
        CHECK(!tunnel::isHello(frame));
        CHECK(tunnel::handleOf(frame) == handle);
        CHECK(tunnel::open(frame, key, kAsked, handle) == payload);

        CHECK_THROWS(tunnel::open(frame, SecretBytes(randomBytes(kAeadKeyBytes)), kAsked, handle));
        CHECK_THROWS(tunnel::open(frame, key, tunnel::Direction::eAnswer, handle));
        CHECK_THROWS(tunnel::open(frame, key, kAsked, auth::sessionHandle(secret, 2)));
        {
            Bytes tampered = frame;
            tampered[tampered.size() - 1] ^= 0x01;
            CHECK_THROWS(tunnel::open(tampered, key, kAsked, handle));
        }
        {
            const Bytes truncated(frame.begin(), frame.end() - 8);
            CHECK_THROWS(tunnel::open(truncated, key, kAsked, handle));
        }
        CHECK(tunnel::carry(handle, key, kAsked, payload) != frame);

        const tunnel::Request back = tunnel::decodeRequest(tunnel::open(frame, key, kAsked, handle));
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

    {
        const SecretBytes secret(randomBytes(32));
        const SecretBytes key = tunnel::deriveTunnelKey(secret, "0123456789abcdef0123456789abcdef");
        const std::string handle = auth::sessionHandle(secret, 1);
        std::set<std::size_t> sizes;
        for (const std::size_t bodyLength : {std::size_t{0}, std::size_t{1}, std::size_t{50}}) {
            tunnel::Request request = sampleRequest();
            request.body = SecretBytes(Bytes(bodyLength, 'x'));
            sizes.insert(tunnel::carry(handle, key, kAsked, tunnel::encodeRequest(request)).size());
        }
        CHECK(sizes.size() == 1);

        tunnel::Request large = sampleRequest();
        large.body = SecretBytes(Bytes(40000, 'x'));
        const std::size_t first = tunnel::carry(handle, key, kAsked, tunnel::encodeRequest(large)).size();
        large.body = SecretBytes(Bytes(40100, 'x'));
        CHECK(tunnel::carry(handle, key, kAsked, tunnel::encodeRequest(large)).size() == first);
    }

    {
        CHECK(!tunnel::isHello(Bytes{'n', 'o', 't', ' ', 'c', 'b', 'o', 'r'}));
        CHECK_THROWS(tunnel::handleOf(Bytes{'n', 'o', 't'}));
        CHECK_THROWS(tunnel::open(Bytes{}, SecretBytes(randomBytes(kAeadKeyBytes)), kAsked, "h"));
    }

    return 0;
} catch (...) {
    return testutil::failed();
}
