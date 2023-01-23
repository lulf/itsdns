use crate::DnsError;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Opcode {
    Query,
    IQuery,
    Status,
}

#[derive(Clone, Copy, PartialEq)]
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

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum QClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

#[derive(Clone, Copy)]
pub(crate) struct DnsMessage<'a> {
    pub(crate) id: u16,
    pub(crate) opcode: Opcode,
    pub(crate) questions: Questions<'a>,
    pub(crate) answers: Answers<'a>,
}

#[derive(Clone, Copy)]
pub(crate) enum Questions<'a> {
    Slice(&'a [Question<'a>]),
    Raw(&'a [u8]),
}

#[derive(Clone, Copy)]
pub(crate) enum Answers<'a> {
    Slice(&'a [Answer<'a>]),
    Raw(&'a [u8]),
}

#[derive(Clone, Copy)]
pub(crate) struct Question<'a> {
    pub(crate) qname: Domain<'a>,
    pub(crate) qtype: QType,
    pub(crate) qclass: QClass,
}

#[derive(Clone, Copy)]
pub(crate) struct Answer<'a> {
    pub(crate) domain: Domain<'a>,
    pub(crate) r#type: QType,
    pub(crate) class: QClass,
    pub(crate) ttl: u32,
    pub(crate) rdata: &'a [u8],
}

impl<'a> Questions<'a> {
    fn len(&self) -> usize {
        match self {
            Questions::Slice(q) => q.len(),
            Questions::Raw(s) => {
                todo!()
            }
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        match self {
            Questions::Slice(questions) => {
                for question in questions.iter() {
                    pos += question.qname.encode(&mut buf[pos..])?;

                    let qtype = (question.qtype as u16).to_be_bytes();
                    buf[pos] = qtype[0];
                    buf[pos + 1] = qtype[1];

                    let qclass = (question.qclass as u16).to_be_bytes();
                    buf[pos + 2] = qclass[0];
                    buf[pos + 3] = qclass[1];

                    pos += 4;
                }
                Ok(pos)
            }
            Questions::Raw(data) => {
                buf[0..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn decode(buf: &'a [u8]) -> Result<Questions<'a>, DnsError> {
        todo!()
    }
}

impl<'a> Answers<'a> {
    fn len(&self) -> usize {
        match self {
            Answers::Slice(q) => q.len(),
            Answers::Raw(s) => {
                todo!()
            }
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        let mut pos = 0;
        match self {
            Answers::Slice(answers) => {
                for answer in answers.iter() {
                    pos += answer.domain.encode(&mut buf[pos..])?;

                    let qtype = (answer.r#type as u16).to_be_bytes();
                    buf[pos] = qtype[0];
                    buf[pos + 1] = qtype[1];
                    pos += 2;

                    let qclass = (answer.class as u16).to_be_bytes();
                    buf[pos] = qclass[0];
                    buf[pos + 1] = qclass[1];
                    pos += 2;

                    buf[pos..pos + 4].copy_from_slice(&answer.ttl.to_be_bytes());
                    pos += 4;

                    buf[pos..pos + 2].copy_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
                    pos += 2;

                    buf[pos..pos + answer.rdata.len()].copy_from_slice(answer.rdata);
                    pos += answer.rdata.len();
                }
                Ok(pos)
            }
            Answers::Raw(data) => {
                buf[0..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn decode(buf: &'a [u8]) -> Result<Answers<'a>, DnsError> {
        todo!()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Domain<'a> {
    String(&'a str),
    Raw(&'a [u8]),
}

impl<'a> Domain<'a> {
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
            Self::Raw(data) => {
                buf[pos..pos + data.len()].copy_from_slice(&data[..]);
                pos += data.len();
            }
        }
        buf[pos] = 0;
        pos += 1;
        Ok(pos)
    }

    fn decode(buf: &'a [u8]) -> Result<(usize, DnsMessage<'a>), DnsError> {
        todo!()
    }
}

impl<'a> DnsMessage<'a> {
    pub(crate) fn encode(&self, buf: &mut [u8]) -> Result<usize, DnsError> {
        assert!(buf.len() >= 8);
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

        buf[4] = self.questions.len() as u8; // QDCOUNT
        buf[5] = self.answers.len() as u8; // ANCOUNT
        buf[6] = 0; // NSCOUNT
        buf[7] = 0; // ARCOUNT

        let mut pos = 8;
        pos += self.questions.encode(&mut buf[pos..])?;

        pos += self.answers.encode(&mut buf[pos..])?;

        Ok(pos)
    }

    pub(crate) fn decode(buf: &'a [u8]) -> Result<DnsMessage<'a>, DnsError> {
        assert!(buf.len() >= 8);
        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let opcode = match buf[2] {
            0 => Ok(Opcode::Query),
            1 => Ok(Opcode::IQuery),
            2 => Ok(Opcode::Status),
            _ => Err(DnsError::Decode),
        }?;

        // TODO: Other bits in buf[2]

        let rcode = buf[3];

        match rcode {
            1 => return Err(DnsError::FormatError),
            2 => return Err(DnsError::ServerFailure),
            3 => return Err(DnsError::NameError),
            4 => return Err(DnsError::NotImplemented),
            5 => return Err(DnsError::Refused),
            _ => {}
        }

        let questions = buf[4] as usize;
        let answers = buf[5] as usize;

        let mut pos = 8;
        for question in 0..questions {
            let (p, domain) = Domain::decode(&buf[pos..])?;
            pos += p;

            let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let qclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
        }

        for answer in 0..answers {
            let (p, domain) = Domain::decode(&buf[pos..])?;
            pos += p;

            let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let qclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;

            let ttl = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            pos += 4;

            let rdata_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]);

            let rdata_len = &buf[pos..pos + rdata_len as usize];
        }

        todo!()
    }
}

#[cfg(tests)]
mod tests {
    #[test]
    fn test_codec() {}
}
