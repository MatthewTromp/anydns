use std::fmt::Display;
use std::net::UdpSocket;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::result::Result;

type Error = Box<dyn std::error::Error>;
type AResult<T> = Result<T, Error>;

const ROOT: &str = "anydns.online";
const MY_IP: Ipv4Addr = Ipv4Addr::new(74, 101, 51, 129);

const MAX_BUFFER_LEN: usize = 512;

pub struct BytePacketBuffer {
    pub buf: [u8; MAX_BUFFER_LEN],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; MAX_BUFFER_LEN],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn _step(&mut self, steps: usize) -> AResult<()> {
        if self.pos + steps >= MAX_BUFFER_LEN {
            Err("End of buffer".into())
        } else {
            self.pos += steps;
            Ok(())
        }
    }

    fn read_bytes(&mut self, steps: usize) -> AResult<Vec<u8>> {
        let out = self.get_range(self.pos, steps)?.to_vec();
        self.pos += steps;
        Ok(out)
    }

    fn seek(&mut self, pos: usize) -> AResult<()> {
        self.pos = pos;

        Ok(())
    }

    fn read(&mut self) -> AResult<u8> {
        if self.pos >= MAX_BUFFER_LEN {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> AResult<u8> {
        if pos >= MAX_BUFFER_LEN {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> AResult<&[u8]> {
        if start + len >= MAX_BUFFER_LEN {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn read_u16(&mut self) -> AResult<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> AResult<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> AResult<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        let max_jumps = 5;
        let mut jumps_performed = 0;
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> AResult<()> {
        if self.pos >= MAX_BUFFER_LEN {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> AResult<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> AResult<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> AResult<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> AResult<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> AResult<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> AResult<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    XRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> AResult<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> AResult<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    SOA,   // 6
    MX,    // 15
    AAAA,  // 28
    OPT,   // 41
    CAA,   // 257
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::OPT => 41,
            QueryType::CAA => 257,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            41 => QueryType::OPT,
            257 => QueryType::CAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub class: u16,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType, class: u16) -> DnsQuestion {
        DnsQuestion { name, qtype, class }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> AResult<DnsQuestion> {
        let mut name = String::new();
        buffer.read_qname(&mut name)?;
        let qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let class = buffer.read_u16()?; // class

        Ok(DnsQuestion {
            name,
            qtype,
            class
        })
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> AResult<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        data: Vec<u8>,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    SOA {
        domain: String,
        ttl: u32,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    }, // 6
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
    OPT {
        domain: String, // Must be 0 (root domain)
        class: u16,     // Requestor udp payload size
        ttl: u32,
        rdlen: u16,
        rdata: Vec<u8>,
    }, // 41
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> AResult<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::SOA => {
                panic!();
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                let data = buffer.read_bytes(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    data,
                    ttl,
                })
            }
            QueryType::CAA => {
                let data = buffer.read_bytes(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    data,
                    ttl,
                })
            }
            QueryType::OPT => {
                let data = buffer.read_bytes(data_len as usize)?;

                Ok(DnsRecord::OPT {
                    domain,
                    class,
                    ttl,
                    rdlen: data_len,
                    rdata: data,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> AResult<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::SOA {
                ref domain,
                ttl,
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let rdlen_pos = buffer.pos();
                buffer.write_u16(0)?;
                
                buffer.write_qname(mname)?;
                buffer.write_qname(rname)?;
                buffer.write_u32(serial)?;
                buffer.write_u32(refresh)?;
                buffer.write_u32(retry)?;
                buffer.write_u32(expire)?;
                buffer.write_u32(minimum)?;

                let rdlen = buffer.pos() - (rdlen_pos + 2);
                buffer.set_u16(rdlen_pos, rdlen as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::OPT {
                ref domain,
                class,
                ttl,
                rdlen,
                ref rdata
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::OPT.to_num())?;
                buffer.write_u16(class)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(rdlen)?;
                for c in rdata {
                    buffer.write_u8(*c)?;
                }
            }
            DnsRecord::UNKNOWN {
                ref domain,
                qtype: _,
                data_len: _,
                data: _,
                ttl: _
            } => {
                println!("Skipping unknown record: {:?}", self);
                buffer.write_qname(domain)?;
//                 buffer.write_u16(qtype)?;
//                 buffer.write_u16(1)?;
//                 buffer.write_u32(ttl)?;
//                 buffer.write_u16(data_len)?;
//                 for c in data {
//                     buffer.write_u8(*c)?
//                 }
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> AResult<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let question = DnsQuestion::read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> AResult<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    /// It's useful to be able to pick a random A record from a packet. When we
    /// get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .find_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
    }

    /// A helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // In practice, these are always NS records in well formed packages.
            // Convert the NS records to a tuple which has only the data we need
            // to make it easy to work with.
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// We'll use the fact that name servers often bundle the corresponding
    /// A records when replying to an NS query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            // Now we need to look for a matching A record in the additional
            // section. Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            // Finally, pick the first valid entry
            .next()
    }

    /// However, not all name servers are as that nice. In certain cases there won't
    /// be any A records in the additional section, and we'll have to perform *another*
    /// lookup in the midst. For this, we introduce a method for returning the host
    /// name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        // Get an iterator over the nameservers in the authorities section
        self.get_ns(qname)
            .map(|(_, host)| host)
            // Finally, pick the first valid entry
            .next()
    }
}

#[derive(Debug)]
enum LookupError {
    InvalidIPv6(String),
    OutOfDomain(String),
    UnsupportedQuery,
    ServerError(Error),
}

impl Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            LookupError::InvalidIPv6(addrerr) => {
                f.write_str("Invalid IPv6 string: ")?;
                addrerr.fmt(f)
            }
            LookupError::OutOfDomain(domainstr) => {
                f.write_str("Invalid domain suffix: ")?;
                domainstr.fmt(f)
            }
            LookupError::UnsupportedQuery => {
                f.write_str("Invalid query")
            }
            LookupError::ServerError(e) => e.fmt(f),
        }
    }

}

impl std::error::Error for LookupError {}

#[derive(Clone)]
enum QnameType<'a> {
    SomeoneElse(&'a str), // Does not end with ROOT
    Me, // ROOT
    Invalid(&'a str), // some.thing.ROOT
    V6(Ipv6Addr), // IP.ROOT
    V6Sub(Ipv6Addr, &'a str), // some.thing.IP.ROOT
}

fn ipv6_parse(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        None
    } else {
        if let Ok(u) = u128::from_str_radix(s, 16) {
            Some(Ipv6Addr::from(u))
        } else {
            None
        }
    }
}

fn qname_type(qname: &str) -> Option<QnameType> {
    match qname.strip_suffix(ROOT) {
        None => Some(QnameType::SomeoneElse(qname)),
        Some("") => Some(QnameType::Me),
        Some(pref) => {
            let pref = pref.strip_suffix(".")?;
            let mut a = pref.split('.').rev();
            // First one should be an ipv6
            let ipraw = a.next().unwrap();
            match ipv6_parse(ipraw) {
                None => Some(QnameType::Invalid(ipraw)),
                Some(ip) => {
                    match pref.strip_suffix(ipraw) {
                        None => panic!("infallible"),
                        Some("") => Some(QnameType::V6(ip)),
                        Some(sub) => Some(QnameType::V6Sub(ip, sub))
                    }
                }
            }
        }
    }
}

// Returns answer, authority
fn lookup(qname: &str, t: QueryType) -> Result<(Option<DnsRecord>, Option<DnsRecord>), LookupError> {
    match (t, qname_type(qname)) {
        (_, None) => Err(LookupError::ServerError("Error in qname parsing".into())),
        
        (_, Some(QnameType::SomeoneElse(s))) => Err(LookupError::OutOfDomain(s.to_string())),

        (_, Some(QnameType::Invalid(s))) => Err(LookupError::InvalidIPv6(s.to_string())),
        
        (QueryType::A, Some(QnameType::Me)) => Ok((Some(DnsRecord::A {
            domain: ROOT.to_string(),
            addr: MY_IP,
            ttl: 60,
        }), None)),

        (QueryType::A, _) => Err(LookupError::UnsupportedQuery),

        // We are the nameserver for ourselves
        (QueryType::NS, Some(QnameType::Me)) => Ok((Some(DnsRecord::NS {
            domain: ROOT.to_string(),
            host: ROOT.to_string(),
            ttl: 60,
        }), None)),
        // The nameserver for an ip subdomain is itself
        (QueryType::NS, Some(QnameType::V6(_))) => Ok((Some(DnsRecord::NS {
            domain: qname.to_string(),
            host: qname.to_string(),
            ttl: 60,
        }), None)),
        
        // This is outside of our scope: you'll have to ask ip's dns 
        (QueryType::NS, Some(QnameType::V6Sub(addr, _))) => refer_to_ip_dns(addr),

        // CAA records: we have none, but we need to tell them that we have none
        // TODO: should we refer to the v6's dns server in the case of V6Sub?
        (QueryType::CAA, Some(QnameType::Me | QnameType::V6(_) | QnameType::V6Sub(_, _))) => Ok(no_record(qname)),

        // We have no AAAA right now
        (QueryType::AAAA, Some(QnameType::Me)) => Ok(no_record(ROOT)),

        // Basic query: this is what we're actually doing
        (QueryType::AAAA, Some(QnameType::V6(addr))) => Ok((Some(DnsRecord::AAAA {
            domain: qname.to_string(),
            addr,
            ttl: 20,
        }), None)),

        // Refer to the ip's nameserver for this sort of stuff
        (QueryType::AAAA | QueryType::SOA, Some(QnameType::V6Sub(addr, _))) => refer_to_ip_dns(addr),

        // Make sure to answer SOA queries so that things don't get angy at me
        (QueryType::SOA, Some(QnameType::Me)) => Ok((Some(this_soa(qname)), None)),

        (QueryType::SOA, Some(QnameType::V6(_))) => Ok(no_record(qname)),

        // Unsupported queries
        (QueryType::MX | QueryType::OPT | QueryType::CNAME | QueryType::UNKNOWN(_), Some(_)) => Err(LookupError::UnsupportedQuery),
    }
}

fn refer_to_ip_dns(addr: Ipv6Addr) -> Result<(Option<DnsRecord>, Option<DnsRecord>), LookupError> {
    let ip_domain = ip_to_domain(addr);
    Ok((None, Some(DnsRecord::NS {
        domain: ip_domain.clone(),
        host: ip_domain,
        ttl: 60
    })))
}

fn no_record(qname: &str) -> (Option<DnsRecord>, Option<DnsRecord>) {
    (None, Some(this_soa(qname)))
}

fn this_soa(qname: &str) -> DnsRecord {
    DnsRecord::SOA {
        domain: qname.to_string(),
        ttl: 60,
        mname: ROOT.to_string(),
        rname: ("contact.".to_string() + ROOT),
        serial: 1,
        refresh: 900,
        retry: 900,
        expire: 1800,
        minimum: 60,
    }
}

pub fn handle_query(socket: &UdpSocket) -> AResult<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    //println!("{:#?}", request);

    let mut packet = DnsPacket::new();

    //packet.resources = request.resources.clone();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = request.header.recursion_desired;
    packet.header.recursion_available = false;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() { 
        println!("Received query: {:?}", question);
        match lookup(&question.name, question.qtype) {
            Ok(result)=> {
                packet.questions.push(question.clone());
                if let Some(answer) = result.0 {
                    packet.answers.push(answer);
                }
                if let Some(authority) = result.1 {
                    packet.authorities.push(authority);
                }
            }
            Err(LookupError::InvalidIPv6(s)) => {
                println!("{} is not a valid ipv6", s);
                packet.header.rescode = ResultCode::NXDOMAIN;
            }
            Err(LookupError::OutOfDomain(s)) => {
                println!("Got query for {}, which is not our domain {}", s, ROOT);
                packet.questions.push(question.clone());
                packet.header.rescode = ResultCode::REFUSED;
            }
            Err(LookupError::UnsupportedQuery) => {
                println!("Unsupported query!");
                packet.questions.push(question.clone());
                packet.header.rescode = ResultCode::NOERROR;
            }
            Err(LookupError::ServerError(e)) => {
                println!("Error during processing: {:?}", e);
                packet.header.rescode = ResultCode::SERVFAIL;
            }
        }
    } else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn ip_to_domain(ip: Ipv6Addr) -> String {
    format!("{:032x}.{ROOT}", u128::from_be_bytes(ip.octets()))
}


#[cfg(test)]
mod tests {
    use super::*;
    const EX_IP: Ipv6Addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
    #[test]
    fn v6_aaaa() {
        let ip_domain = ip_to_domain(EX_IP);
        let (resp, auth) = lookup(&ip_domain, QueryType::AAAA).unwrap();
        assert!(auth.is_none());
        match resp {
            Some(DnsRecord::AAAA { domain, addr, ttl: _ }) => {
                assert_eq!(ip_domain, domain);
                assert_eq!(EX_IP, addr);
            }
            a => panic!("{:?}", a),
        }
    }
    #[test]
    fn v6_a() {
        let ip_domain = ip_to_domain(EX_IP);
        match lookup(&ip_domain, QueryType::A) {
            Err(LookupError::UnsupportedQuery) => (),
            a => panic!("{:?}", a),
        }
    }
    #[test]
    fn self_a() {
        let (resp, auth) = lookup(ROOT, QueryType::A).unwrap();
        assert!(auth.is_none());
        match resp {
            Some(DnsRecord::A { domain, addr, ttl: _ }) => {
                assert_eq!(&domain, ROOT);
                assert_eq!(MY_IP, addr);
            }
            a => panic!("{:?}", a),
        }
    }
    #[test]
    fn self_aaaa() {
        let (resp, auth) = lookup(ROOT, QueryType::AAAA).unwrap();
        assert!(resp.is_none());
        match auth {
            Some(DnsRecord::SOA { domain, ttl, mname, rname, serial, refresh, retry, expire, minimum }) => {
                assert_eq!(&domain, ROOT);
            }
            a => panic!("{a:?}"),
        }
    }
    #[test]
    fn self_na() {
        let (resp, auth) = lookup(ROOT, QueryType::NS).unwrap();
        assert!(auth.is_none());
        match resp {
            Some(DnsRecord::NS { domain, host, ttl: _ttl }) => {
                assert_eq!(&domain, ROOT);
                assert_eq!(&host, ROOT);
            }
            _ => panic!(),
        }
    }
}
