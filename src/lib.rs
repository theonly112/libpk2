#![allow(dead_code)]

use std::fs::File;
use std::path::Path;
use std::mem::size_of;
use std::string::String;
use std::io::{Seek, SeekFrom,Read, Result, Error, ErrorKind};
use blowfish::Blowfish;
use std::collections::HashMap;

mod blowfish;

#[test]
fn it_works() {
	let mut reader = match Pk2Reader::new(Path::new("D:/Silkroad/Januera/Media.pk2")) {
		Ok(reader) => reader,
		Err(e) => panic!("{}",e)
	};		
	reader.get_file(&"DIVISIONINFO.TXT".to_string());
}

struct Pk2Reader {
	file : Option<File>,
	blowfish : Blowfish,
	entires : HashMap<String,Pk2Entry>
}

struct Pk2Header {
	name : [u8; 30],
	version : [u8; 4],
	encryption : u8,
	verify : [u8; 16],
	reserved : [u8; 205]
}

#[repr(C, packed)]
struct Pk2Entry {
	pub entry_type : u8, //2 = file, 1 = folder, 0 = null entry
	name : [u8; 81],
	access_time : u64,
	create_time : u64, 
	modify_time : u64,
	position : i64,
	size : u32,
	next_chain : i64,
	padding : [u8;2] 
}

// Required since clone for [T;size] is only implemented for size <= 32
impl Clone for Pk2Entry {
	fn clone(&self) ->  Self {
		let mut entry = Pk2Entry {
			entry_type : self.entry_type,
			name : [0; 81],
			access_time : self.access_time,
			create_time : self.create_time,
			modify_time : self.modify_time,
			position : self.position,
			size : self.size,
			next_chain : self.next_chain,
			padding : self.padding.clone()
		};
		for i in 0..81 {
			entry.name[i] = self.name[i];
		}
		return entry;
	}
}


#[repr(C, packed)]
struct Pk2EntryBlock {
	pub entries : [Pk2Entry; 20]
}

impl Pk2Reader {
	pub fn new(path : &Path) -> Result<Pk2Reader> {
		let mut reader = Pk2Reader {
			file : None,
			blowfish : Blowfish::new(),
			entires : HashMap::new()
		};
		let key : [u8;6] = [0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8];
		reader.blowfish.initialize(&key[..]);
		
		reader.file = match File::open(path) {
			Ok(file) => Some(file),
			Err(e) => return Err(e)
		};
		
		let mut header_buff : [u8; 256] = [0;256];
		let size = match reader.file {
			Some(ref mut file) => file.read(&mut header_buff [..]).unwrap(),
			None => 0
		};
				
		if size != size_of::<Pk2Header>() {
			return Err(Error::new(ErrorKind::Other, "Could not reader pk2 header"));
		}
	
		let header : Pk2Header = unsafe {
			std::mem::transmute::<[u8;256],Pk2Header>(header_buff)
		};
		
		let x : &[_] = &['\0','\n'];
		let name_dirty = String::from_utf8_lossy(&header.name[..]);
		let name = name_dirty.trim_right_matches(x);
	
		if name != "JoyMax File Manager!" {
			return Err(Error::new(ErrorKind::Other, "Not a valid pk2 file"));
		}			
		
		try!(reader.read_block(256));
		
		Ok(reader)
	}
	
	pub fn get_file(&mut self, filename : &String) -> Result<Vec<u8>> {
			let entry = match self.entires.get(filename) {
				Some(entry) => entry,
				None => return Err(Error::new(ErrorKind::Other, "Could not find file."))
			};
			
			let mut file_buffer = Vec::<u8>::with_capacity(entry.size as usize);
			unsafe {
				file_buffer.set_len(entry.size as usize)
			}
			let size = match self.file {
				Some(ref mut file) =>  {
					try!(file.seek(SeekFrom::Start(entry.position as u64)));
					try!(file.read(&mut file_buffer[..]))
				},
				None => 0
			};
			
			if size != entry.size as usize {
				return Err(Error::new(ErrorKind::Other, "Could not read file from pk2 file."));
			}
			Ok(file_buffer)		
	}
	
	fn read_block(&mut self, pos : u64) -> Result<()> {			
		let mut block_buffer = Vec::<u8>::with_capacity(2560);
		//set_len is required since file.read(..) only reads block_buffer.len elements
		unsafe {
			block_buffer.set_len(2560)
		}
		
		let bytes_read = match self.file {
			Some(ref mut file) =>  {
				try!(file.seek(SeekFrom::Start(pos)));
				try!(file.read(&mut block_buffer[..]))
			},
			None => 0
		};
		
		if bytes_read != 2560 {
			return Err(Error::new(ErrorKind::Other, "Could not read Pk2EntryBlock from file."));
		}
		
		//file is encoded with blowfish
		let decoded_buffer = self.blowfish.decode(block_buffer);
		
		//cast decoded byte buffer to Pk2EntryBlock
		let block : &Pk2EntryBlock = unsafe {
			 &*(decoded_buffer[..].as_ptr() as *const Pk2EntryBlock)
		};
		
		//to store positions of sub folder
		let mut folders = Vec::<u64>::new();
		
		
		for i in 0..20 {
			let ref entry = block.entries[i];
			if entry.entry_type == 0 {
				continue;
			}
			
			//clean up the c string
			let name_dirty = String::from_utf8_lossy(&entry.name[..]);
			let end = name_dirty.find('\0').unwrap();
			let mut name = name_dirty.to_string();
			name.truncate(end);
	
			match entry.entry_type {
				1 => { 
					//println!("[{}]", name); 
					if name != ".".to_string() && name != "..".to_string() {
						folders.push(entry.position as u64);
					}
				},
				//2 => println!("{}", name),
				//0 => println!("*null_entry*"),
				_ => {}
			};
			self.entires.insert(name.to_string(), entry.clone());
		}
		
				
		for f in folders {
			try!(self.read_block(f))
		}
		
		// A directory can obviously have more than 20 entries. 
		// Therefore if it does, the last entry of the block has its "next_chain"
		// property set to address of the next block.
		if block.entries[19].next_chain != 0 {
			try!(self.read_block(block.entries[19].next_chain as u64));
		}
		
		Ok(())
	}
}