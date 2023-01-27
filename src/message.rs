#![allow(dead_code)]
use crate::DnsError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Opcode {
    Query,
    IQuery,
    Status,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum QType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255,
}

impl TryFrom<u16> for QType {
    type Error = DnsError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            3 => Ok(Self::MD),
            4 => Ok(Self::MF),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            7 => Ok(Self::MB),
            8 => Ok(Self::MG),
            9 => Ok(Self::MR),
            10 => Ok(Self::NULL),
            11 => Ok(Self::WKS),
            12 => Ok(Self::PTR),
            13 => Ok(Self::HINFO),
            14 => Ok(Self::MINFO),
            15 => Ok(Self::MX),
            16 => Ok(Self::TXT),
            252 => Ok(Self::AXFR),
            253 => Ok(Self::MAILB),
            254 => Ok(Self::MAILA),
            255 => Ok(Self::ALL),
            _ => Err(DnsError::Decode),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum QClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl TryFrom<u16> for QClass {
    type Error = DnsError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IN),
            2 => Ok(Self::CS),
            3 => Ok(Self::CH),
            4 => Ok(Self::HS),
            _ => Err(DnsError::Decode),
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub(crate) struct DnsMessage<'a> {
    pub(crate) id: u16,
    pub(crate) opcode: Opcode,
    pub(crate) questions: Questions<'a>,
    pub(crate) answers: Answers<'a>,
}

#[derive(Clone, Debug, Copy)]
pub(crate) enum Questions<'a> {
    Slice(&'a [Question<'a>]),
    Raw {
        message: &'a [u8],
        count: usize,
        data: &'a [u8],
    },
}

#[derive(Clone, Debug, Copy)]
pub(crate) enum Answers<'a> {
    Slice(&'a [Answer<'a>]),
    Raw {
        message: &'a [u8],
        count: usize,
        data: &'a [u8],
    },
}

#[derive(Clone, Debug, Copy)]
pub(crate) struct Question<'a> {
    pub(crate) qname: Domain<'a>,
    pub(crate) qtype: QType,
    pub(crate) qclass: QClass,
}

#[derive(Clone, Debug, Copy)]
pub(crate) struct Answer<'a> {
    pub(crate) domain: Domain<'a>,
    pub(crate) r#type: QType,
    pub(crate) class: QClass,
    pub(crate) ttl: u32,
    pub(crate) rdata: &'a [u8],
}

impl<'a> Question<'a> {
    fn decode(data: &'a [u8], message: &'a [u8]) -> Result<(usize, Question<'a>), DnsError> {
        let mut pos = 0;
        let (p, qname) = Domain::decode(&data[pos..], message)?;
        pos += p;

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]).try_into()?;
        pos += 2;

        let qclass = u16::from_be_bytes([data[pos], data[pos + 1]]).try_into()?;
        pos += 2;
        Ok((
            pos,
            Question {
                qname,
                qtype,
                qclass,
            },
        ))
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        pos += self.qname.encode(&mut buf[pos..])?;

        let qtype = (self.qtype as u16).to_be_bytes();
        buf[pos] = qtype[0];
        buf[pos + 1] = qtype[1];
        pos += 2;

        let qclass = (self.qclass as u16).to_be_bytes();
        buf[pos] = qclass[0];
        buf[pos + 1] = qclass[1];
        pos += 2;
        Ok(pos)
    }
}

impl<'a> Answer<'a> {
    fn decode(data: &'a [u8], message: &'a [u8]) -> Result<(usize, Answer<'a>), DnsError> {
        let mut pos = 0;
        let (p, domain) = Domain::decode(&data[pos..], message)?;
        pos += p;

        let r#type = u16::from_be_bytes([data[pos], data[pos + 1]]).try_into()?;
        pos += 2;

        let class = u16::from_be_bytes([data[pos], data[pos + 1]]).try_into()?;
        pos += 2;

        let ttl = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let rdata_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let rdata = &data[pos..pos + rdata_len];

        Ok((
            pos,
            Answer {
                domain,
                r#type,
                class,
                ttl,
                rdata,
            },
        ))
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        pos += self.domain.encode(&mut buf[pos..])?;

        let qtype = (self.r#type as u16).to_be_bytes();
        buf[pos] = qtype[0];
        buf[pos + 1] = qtype[1];
        pos += 2;

        let qclass = (self.class as u16).to_be_bytes();
        buf[pos] = qclass[0];
        buf[pos + 1] = qclass[1];
        pos += 2;

        buf[pos..pos + 4].copy_from_slice(&self.ttl.to_be_bytes());
        pos += 4;

        buf[pos..pos + 2].copy_from_slice(&(self.rdata.len() as u16).to_be_bytes());
        pos += 2;

        buf[pos..pos + self.rdata.len()].copy_from_slice(self.rdata);
        pos += self.rdata.len();
        Ok(pos)
    }
}

impl<'a> Questions<'a> {
    fn count(&self) -> usize {
        match self {
            Questions::Slice(q) => q.len(),
            Questions::Raw {
                count,
                data: _,
                message: _,
            } => *count,
        }
    }

    fn get(&'a self, i: usize) -> Result<Option<Question<'a>>, DnsError> {
        match self {
            Self::Slice(qs) => Ok(qs.get(i).copied()),
            Self::Raw {
                count,
                data,
                message,
            } => {
                if i < *count {
                    let mut pos = 0;
                    for question in 0..*count {
                        let (p, q) = Question::decode(&data[pos..], message)?;
                        if question == i {
                            return Ok(Some(q));
                        }
                        pos += p;
                    }
                }
                Ok(None)
            }
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        match self {
            Questions::Slice(questions) => {
                for question in questions.iter() {
                    pos += question.encode(&mut buf[pos..])?;
                }
                Ok(pos)
            }
            Questions::Raw {
                count: _,
                message: _,
                data,
            } => {
                buf[0..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn decode(
        count: usize,
        buf: &'a [u8],
        message: &'a [u8],
    ) -> Result<(usize, Questions<'a>), DnsError> {
        let mut pos = 0;
        for _question in 0..count {
            let (p, _domain) = Domain::decode(&buf[pos..], message)?;
            pos += p;

            let _qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let _qclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
        }

        Ok((
            pos,
            Questions::Raw {
                count,
                message,
                data: &buf[..pos],
            },
        ))
    }
}

impl<'a> Answers<'a> {
    pub fn count(&self) -> usize {
        match self {
            Answers::Slice(q) => q.len(),
            Answers::Raw {
                count,
                message: _,
                data: _,
            } => *count,
        }
    }

    pub fn get(&'a self, i: usize) -> Result<Option<Answer<'a>>, DnsError> {
        match self {
            Self::Slice(qs) => Ok(qs.get(i).copied()),
            Self::Raw {
                count,
                data,
                message,
            } => {
                if i < *count {
                    let mut pos = 0;
                    for answer in 0..*count {
                        let (p, a) = Answer::decode(&data[pos..], message)?;
                        if answer == i {
                            return Ok(Some(a));
                        }
                        pos += p;
                    }
                }
                Ok(None)
            }
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        match self {
            Answers::Slice(answers) => {
                for answer in answers.iter() {
                    pos += answer.encode(&mut buf[pos..])?;
                }
                Ok(pos)
            }
            Answers::Raw {
                count: _,
                message: _,
                data,
            } => {
                buf[0..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn decode(
        count: usize,
        buf: &'a [u8],
        message: &'a [u8],
    ) -> Result<(usize, Answers<'a>), DnsError> {
        let mut pos = 0;
        for _answer in 0..count {
            let (p, _) = Domain::decode(&buf[pos..], message)?;
            pos += p;

            let _qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let _qclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let _ttl = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            pos += 4;

            let rdata_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            pos += rdata_len as usize;
        }
        Ok((
            pos,
            Answers::Raw {
                count,
                data: &buf[..pos],
                message,
            },
        ))
    }
}

#[derive(Clone, Debug, Copy)]
pub(crate) enum Domain<'a> {
    String(&'a str),
    Raw { data: &'a [u8], message: &'a [u8] },
}

struct DomainIter<'a> {
    domain: &'a Domain<'a>,
    pos: usize,
    len: usize,
    ptr: Option<usize>,
    first: bool,
}

impl<'a> Iterator for DomainIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self.domain {
            Domain::String(s) => {
                let b = s.as_bytes();
                if self.pos < b.len() {
                    let pos = self.pos;
                    self.pos += 1;
                    Some(b[pos])
                } else {
                    None
                }
            }
            Domain::Raw { data, message } => {
                let mut ret = None;
                loop {
                    let data = if let Some(p) = self.ptr {
                        &message[p..]
                    } else {
                        data
                    };
                    let pos = self.pos;
                    if self.len > 0 {
                        self.pos += 1;
                        self.len -= 1;
                        ret.replace(data[pos]);
                        break;
                    } else if data[pos] & 0xC0 != 0 {
                        self.ptr.replace(u16::from_be_bytes([data[pos] & 0x3F, data[pos + 1]]) as usize);
                        self.pos = 0;
                        self.len = 0;
                    } else if data[pos] == 0 {
                        break;
                    } else {
                        self.len = data[pos] as usize;
                        self.pos += 1;
                        if !self.first {
                            ret.replace('.' as u8);
                            break;
                        }
                    }
                }
                self.first = false;
                ret
            }
        }
    }
}

impl<'a> PartialEq for Domain<'a> {
    fn eq(&self, other: &Self) -> bool {
        let mut lit = self.iter();
        let mut rit = other.iter();
        loop {
            match (lit.next(), rit.next()) {
                (Some(l), Some(r)) => {
                    if l != r {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a> Domain<'a> {
    fn iter(&'a self) -> DomainIter<'a> {
        DomainIter {
            domain: self,
            pos: 0,
            len: 0,
            ptr: None,
            first: true,
        }
    }
    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        match self {
            Self::String(host) => {
                let mut labels = host.split('.');
                while let Some(label) = labels.next() {
                    let label = label.as_bytes();
                    let l = label.len().min(255);
                    buf[pos] = l as u8;
                    pos += 1;

                    buf[pos..pos + l].copy_from_slice(&label[..l]);
                    pos += l;
                }
            }
            Self::Raw { data, message: _ } => {
                buf[pos..pos + data.len()].copy_from_slice(&data[..]);
                pos += data.len();
            }
        }
        buf[pos] = 0;
        pos += 1;
        Ok(pos)
    }

    fn decode(buf: &'a [u8], message: &'a [u8]) -> Result<(usize, Domain<'a>), DnsError> {
        let mut pos = 0;
        loop {
            let len = buf[pos];
            if len & 0xC0 != 0 {
                pos += 2;
                break;
            } else {
                pos += len as usize + 1;
            }

            if len == 0 {
                break;
            }
        }
        Ok((
            pos,
            Domain::Raw {
                data: &buf[..pos],
                message,
            },
        ))
    }
}

impl<'a> DnsMessage<'a> {
    pub(crate) fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        assert!(buf.len() >= 12);
        let id = self.id.to_be_bytes();
        buf[0] = id[0];
        buf[1] = id[1];

        // bit 0 - query
        // bit 1-4 - opcode
        // bit 5 - authorative (for responses, not set)
        // bit 6 - truncation (not set)
        // bit 7 - recursion (not set)
        buf[2] = match self.opcode {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
        } << 3;

        buf[3] = 0;

        buf[4..6].copy_from_slice(&(self.questions.count() as u16).to_be_bytes()); // QDCOUNT
        buf[6..8].copy_from_slice(&(self.answers.count() as u16).to_be_bytes()); // ANCOUNT
        buf[8] = 0; // NSCOUNT
        buf[9] = 0; // NSCOUNT
        buf[10] = 0; // ARCOUNT
        buf[11] = 0; // ARCOUNT

        let mut pos = 12;
        pos += self.questions.encode(&mut buf[pos..])?;

        pos += self.answers.encode(&mut buf[pos..])?;

        Ok(pos)
    }

    pub(crate) fn decode(buf: &'a [u8]) -> Result<DnsMessage<'a>, DnsError> {
        assert!(buf.len() >= 12);
        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let opcode = match (buf[2] >> 3) & 0xF {
            0 => Ok(Opcode::Query),
            1 => Ok(Opcode::IQuery),
            2 => Ok(Opcode::Status),
            _ => Err(DnsError::Decode),
        }?;

        // TODO: Other bits in buf[2]

        let rcode = buf[3] & 0xF;

        match rcode {
            1 => return Err(DnsError::FormatError),
            2 => return Err(DnsError::ServerFailure),
            3 => return Err(DnsError::NameError),
            4 => return Err(DnsError::NotImplemented),
            5 => return Err(DnsError::Refused),
            _ => {}
        }

        let questions = u16::from_be_bytes([buf[4], buf[5]]);
        let answers = u16::from_be_bytes([buf[6], buf[7]]);

        // Skip NSCOUNT, ARCOUNT
        let mut pos = 12;

        let (p, questions) = Questions::decode(questions as usize, &buf[pos..], buf)?;
        pos += p;

        let (_p, answers) = Answers::decode(answers as usize, &buf[pos..], buf)?;

        Ok(DnsMessage {
            id,
            opcode,
            questions,
            answers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn test_query() {
        let mut buf = [0; 1024];

        let len = DnsMessage {
            id: 2,
            opcode: Opcode::Query,
            questions: Questions::Slice(&[Question {
                qname: Domain::String("google.com"),
                qtype: QType::A,
                qclass: QClass::IN,
            }]),
            answers: Answers::Slice(&[]),
        }
        .encode(&mut buf[..])
        .unwrap();
        assert_eq!(len, 28);

        let m = DnsMessage::decode(&buf[..len]).unwrap();

        let question = m.questions.get(0).unwrap().unwrap();
        assert_eq!(Domain::String("google.com"), question.qname);
    }
}
