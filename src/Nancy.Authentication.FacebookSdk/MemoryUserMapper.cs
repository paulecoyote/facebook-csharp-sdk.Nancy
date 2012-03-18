using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nancy.Authentication.Forms;
using System.Security.Cryptography;
using System.Threading;

namespace Nancy.Authentication.FacebookSdk
{
    public class MemoryUserMapper<T> : IUserMapper where T:Security.IUserIdentity
    {
        public Security.IUserIdentity GetUserFromIdentifier(Guid identifier)
        {
            try
            {
                lookupLock.EnterReadLock();
                Container container;
                if (lookup.TryGetValue(identifier, out container))
                {
                    return container.Value;
                }
                
                return null;
            }
            finally
            {
                lookupLock.ExitReadLock();
            }
        }

        public Guid SetUser(T id)
        {
            var newIdentifier = CreateMoreSecureGuid();
            var container = new Container() { Value = id };

            lookupLock.EnterWriteLock();
            lookup[newIdentifier] = container;
            lookupLock.ExitWriteLock();
            return newIdentifier;
        }

        private static Guid CreateMoreSecureGuid()
        {
            // See section 4.4 of http://www.ietf.org/rfc/rfc4122.txt
            var randomBytes = new byte[16];
            rngCsp.GetBytes(randomBytes);
            var a = BitConverter.ToUInt32(randomBytes, 0);
            var b = BitConverter.ToUInt16(randomBytes, 4);

            // Mask 4 to be rfc4122 compliant Guid
            var c = (UInt16)((BitConverter.ToUInt16(randomBytes, 6) & 0xFFF) | 0x4000);
            var d = (byte)(randomBytes[8] & (0x3 | 0x8));
            return new Guid(
                a,
                b,
                c,
                d,
                randomBytes[9],
                randomBytes[10],
                randomBytes[11],
                randomBytes[12],
                randomBytes[13],
                randomBytes[14],
                randomBytes[15]);
        }

        private class Container
        {
            public DateTime DateSet = DateTime.Now;
            public T Value;
        }

        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        private Dictionary<Guid, Container> lookup = new Dictionary<Guid, Container>();
        private ReaderWriterLockSlim lookupLock = new ReaderWriterLockSlim();
    }
}
