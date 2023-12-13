# anydns
Anydns is a DNS server which has a subdomain for every IPv6 address (yes, including yours!). It currently has one running implementation, at anydns.online.

## How do I get a domain name?
You already have one! The anydns.online domain server is completely stateless: when someone sends it a DNS query with a correctly formatted domain name, it extracts the IP address from the domain name and returns it!

## What's my domain name?
Take your public IPv6 address, fully expand it out, remove all the colons, add .anydns.online, and that's it! For instance, the IP address 2001:db8::8a2e:370:7334 has a domain at 20010db80000000000008a2e03707334.anydns.online. You can use it to host a website, or even a DNS server of your own! (probably, if I've set up NS records properly. If anyone actually does this please email me to let me know how it goes.)

## So, you'll host a website for me?
No! This is just a DNS record that points to your IP address, so if someone goes to [your IPv6].anydns.online, they'll get pointed to your IP address, the same as if they'd just put your IP address in their address bar.

## What happens if my IP address changes?
Then everyone will need to start using the new one, just the same as if they'd been using your IP address directly in the first place!

## It sounds like, if I want to host a website, using anydns.online is basically the same as giving people my IP address but with an extra step.
Yep!

## Why would I want this?
If you want to encrypt your server's communications, you need an SSL certificate. While in principle, SSL certs can be issued for IP addresses, and some (paid) CAs do offer this, [LetsEncrypt does not](https://community.letsencrypt.org/t/ssl-on-a-ip-instead-of-domain/90635). So, if you want SSL, you need a domain name.

## Why would I want an SSL certificate for my IP address?
Plenty of reasons! Just to take an example, let's say you want to send a file to someone else. Currently, there are no good ways to do this that don't require either the use of an intermediary server or for your counterparty to have some weird software on their computer. But why? The internet was designed for this sort of peer-to-peer communication. Just start up a server on your computer which serves the file and send them the link!

There are many things which make this impractical: firewalls and network address translation (which itself is due to the continued dominance of IPv4) are the two that come most prominently to mind. But the inability to easily encrypt this comminication is also a problem. The best way to solve this would be for letsencrypt to allow certificates for IP addresses. In the meantime, anydns provides an alternative.

## Okay cool, I'm gonna go use this now.
I should probably warn you, [LetsEncrypt limits a domain to 50 new certificates per week](https://letsencrypt.org/docs/rate-limits/). So, if anyone starts using anydns to any signficant degree, I'm probably going to hit that limit pretty quickly. But I still encourage you to use it! If nothing else, hitting the registration limit gives me an argument that anydns.online is popular enough to justify being put on the public suffix list, which would remove this limit.