using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nancy.Tests;
using Xunit;
using FakeItEasy;

namespace Nancy.Authentication.FacebookSdk.Tests
{
    public class NancyFacebookUserMapperFixture
    {
        [Fact]
        public void Should_get_rfc4122_guid_when_user_set()
        {
            // See section 4.4 of http://www.ietf.org/rfc/rfc4122.txt
            var id = A.Fake<NancyFacebookIdentity>();
            var guid = mapper.SetUser(id);
            var guidBytes = guid.ToByteArray();

            var c = BitConverter.ToUInt16(guidBytes, 6);
            Assert.True((c & 0x4000) == 0x4000);

            var d = (byte)(guidBytes[8] & (0x3 | 0x8));
            Assert.True((d & (0x3 | 0x8)) != 0);
        }

        [Fact]
        public void Should_get_user_that_is_stored_by_guid()
        {
            var id = A.Fake<NancyFacebookIdentity>();
            var identifier = mapper.SetUser(id);
            var idBack = mapper.GetUserFromIdentifier(identifier);

            id.ShouldBeSameAs(idBack);
        }

        MemoryUserMapper<NancyFacebookIdentity> mapper = new MemoryUserMapper<NancyFacebookIdentity>();
    }
}
