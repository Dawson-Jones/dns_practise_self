use std::{net::{Ipv4Addr, Ipv6Addr}};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer { 
            buf: [0; 512], 
            pos: 0, 
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }

        Ok(self.buf[pos])
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }

        Ok(&self.buf[start..start+len])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delimiter = "";

        loop {
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;
            if (len & 0xc0) == 0xc0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                // 如果前两位是1, 那么是跳转指令, 用于压缩
                // 异或 0xc0 来消除前两位
                // 所以跳转最大可以是 (1 << 14) - 1
                let b2 = self.get(pos + 1)? as u16;
                let offset = (len as u16 ^ 0xc0) << 8 | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                // len 读过了, 所有向前移动一个
                pos += 1;

                if len == 0 {
                    break;
                }

                outstr.push_str(delimiter);

                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                // 放在后面是为了最后一个就可以不放了
                // 比如 google.com, 而不必是 google.com.
                delimiter = ".";
                pos += len as usize;
            }

        }

        // 没有 jump 说明要一个个读, 所以 pos 要对齐过来
        // 而 如果 jump 了, self.seek(pos + 2)
        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }

        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        return self.write(val);
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        // val is a little endian, the high address need to put first
        self.write((val >> 8) as u8)?;
        self.write((val & 0xff) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write((val >> 24) as u8)?;
        self.write((val >> 16) as u8)?;
        self.write((val >> 8) as u8)?;
        self.write((val >> 0) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f { // 因为 label len 的前两个位有可能代表 jump, 所以 len 就只能用后面的 6 位了
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

    fn set(&mut self, pos: usize, val: u8) {
        self.buf[pos] = val;
    }

    fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val >> 8 & 0xff) as u8);
        self.set(pos+1, (val >> 0 & 0xff) as u8);
    }

}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR  = 0,
    FORMERR  = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP   = 4,
    REFUSED  = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> Self {
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
    pub id: u16,

    pub response: bool,                 // 1 bit
    pub opcode: u8,                     // 4 bit
    pub authoritative_answer: bool,     // 1 bit
    pub truncated_message: bool,        // 1 bit
    pub recursion_desired: bool,        // 1 bit

    pub recursion_available: bool,      // 1 bit
    pub z: bool,                        // 1 bit
    pub authed_data: bool,              // 1 bit
    pub checking_disabled: bool,        // 1 bit
    pub rescode: ResultCode,            // 4 bit

    pub questions: u16,                 // 16 bit
    pub answers: u16,                   // 16 bit
    pub authoritative_entries: u16,     // 16 bit
    pub resource_entries: u16,          // 16 bit   Additional Section
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader { 
            id: 0, 

            response: false, 
            opcode: 0, 
            authoritative_answer: false, 
            truncated_message: false, 
            recursion_desired: false, 

            recursion_available: false, 
            z: false, 
            authed_data: false, 
            checking_disabled: false, 
            rescode: ResultCode::NOERROR, 
            questions: 0, 
            answers: 0, 
            authoritative_entries: 0, 
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        // let flags = buffer.read_u16()?;
        // let a = (flags >> 8) as u8;
        // let b = (flags & 0xff) as u8;
        let a = buffer.read()?;
        let b = buffer.read()?;

        // big endian
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0f;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0f);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }


    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        // buffer is a big endian
        buffer.write_u8(
            (self.response as u8) << 7 |
            self.opcode << 3 |
            (self.authoritative_answer as u8) << 2 |
            (self.truncated_message as u8) << 1 |
            (self.recursion_desired as u8)
        )?;

        buffer.write_u8(
            (self.recursion_available as u8) << 7 |
            (self.z as u8) << 6 |
            (self.authed_data as u8) << 5 |
            (self.checking_disabled as u8) << 4 |
            (self.rescode as u8)
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
    A,      // 1
    NS,     // 2
    CNAME,  // 5
    MX,     // 15
    AAAA,   // 28  
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,   // 16 bit
}

// name
// type: 16
// class: 16
impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { 
            name, 
            qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        // buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?; // 1 is Class 0x0001

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
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

// name
// type: 16
// class: 16
// ttl: 32
// data length: 16
// address: 
impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xff) as u8,
                    ((raw_addr >> 16) & 0xff) as u8,
                    ((raw_addr >> 8) & 0xff) as u8,
                    ((raw_addr >> 0) & 0xff) as u8,
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

                Ok(DnsRecord::AAAA { domain , addr, ttl })
            }
            QueryType::NS | QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::NS { domain, host, ttl })
            },
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::MX { domain, priority, host, ttl })
            },

            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize);
                Ok(DnsRecord::UNKNOWN { domain, qtype: qtype_num, data_len, ttl })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A { ref domain, ref addr, ttl } => {
                buffer.write_qname(domain)?;   // TODO: 压缩
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(0x0001)?;  // class
                buffer.write_u32(ttl)?;
                buffer.write_u16(0x0004)?;  // data length. octets.len()?

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS { ref domain, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(0x0001)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;
                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::CNAME { ref domain, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(0x0001)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();

                buffer.write_u16(0)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::MX { ref domain, priority, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(0x0001)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                
                buffer.write_u16(0)?;
                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::AAAA { ref domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(0x0001)?;  // class
                buffer.write_u32(ttl)?;
                buffer.write_u16(0x0010)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            },

            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            },
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questioins: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket { 
            header: DnsHeader::new(), 
            questioins: Vec::new(), 
            answers: Vec::new(), 
            authorities: Vec::new(), 
            resources:  Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questioins.push(question);
        }

        for _ in 0..result.header.answers {
            let answer = DnsRecord::read(buffer)?;
            result.answers.push(answer);
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

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questioins.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;
        self.header.write(buffer)?;

        for question in &self.questioins {
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
}