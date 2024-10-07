use std::cmp::Ordering;

use bn::{AffineG1, AffineG2, Fq, Fq2};

use crate::{
    constants::{CompressedPointFlag, MASK},
    error::Error,
};

use crate::wasm_bindgen;

#[wasm_bindgen]
/// Test
extern {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool, Error> {
    if first_byte != 0 {
        return Ok(false);
    }
    for &b in buf {
        if b != 0 {
            return Ok(false);
        }
    }

    Ok(true)
}

pub(crate) fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), Error> {
    log(&format!("buf: {:?}", buf));
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    };

    log(&format!("buf: {:?}", buf));

    let m_data: u8 = buf[0] & MASK;
    log(&format!("MASK: {:?}", MASK));
    log(&format!("m_data: {:?} CompressedPointFlag::Infinity = {:?}",
        m_data, u8::from(CompressedPointFlag::Infinity)));
    if m_data == u8::from(CompressedPointFlag::Infinity) {
        log(&format!("infinity match #1"));
        
        // Check if the first byte (without the mask) is zero
        let first_byte_without_mask = buf[0] & !MASK;
        log(&format!("First byte without mask: {:?}", first_byte_without_mask));
        
        // Check if the remaining bytes are all zero
        let remaining_bytes_zeroed = is_zeroed(first_byte_without_mask, &buf[1..32]);
        log(&format!("Remaining bytes zeroed: {:?}", remaining_bytes_zeroed));
        
        match remaining_bytes_zeroed {
            Ok(true) => {
                log("All bytes are zero as expected for infinity point");
            },
            Ok(false) => {
                log("Non-zero bytes found where all zeros expected");
                return Err(Error::InvalidPoint);
            },
            Err(e) => {
                log(&format!("Error checking zeroed bytes: {:?}", e));
                return Err(Error::InvalidPoint);
            }
        }
        log(&format!("infinity match #2"));
        Ok((Fq::zero(), CompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes).expect("Failed to convert x bytes to Fq");

        Ok((x, m_data.into()))
    }
}

pub(crate) fn compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    let (x, m_data) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == CompressedPointFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressedPointFlag::Negative {
        final_y = -y;
    }

    AffineG1::new(x, final_y).map_err(Error::Group)
}

pub(crate) fn unchecked_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    log(&format!("buf: {:?}", buf));
    let (x, m_data) = deserialize_with_flags(buf)?;
    log(&format!("x: {:?}", x));
    log(&format!("m_data: {:?}", m_data));
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;
    log(&format!("y: {:?}", y));
    log(&format!("neg_y: {:?}", neg_y));

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == CompressedPointFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressedPointFlag::Negative {
        final_y = -y;
    }

    log(&format!("final_y: {:?}", final_y));

    Ok(AffineG1::new_unchecked(x, final_y))
}

pub fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };
    
    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;
    AffineG1::new(x, y).map_err(Error::Group)
}

pub(crate) fn compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).map_err(Error::Field)?;
    let x = Fq2::new(x0, x1);

    if flag == CompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;

    match flag {
        CompressedPointFlag::Positive => Ok(AffineG2::new(x, y).map_err(Error::Group)?),
        CompressedPointFlag::Negative => Ok(AffineG2::new(x, neg_y).map_err(Error::Group)?),
        _ => Err(Error::InvalidPoint),
    }
}

pub(crate) fn unchecked_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).map_err(Error::Field)?;
    let x = Fq2::new(x0, x1);

    if flag == CompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;

    match flag {
        CompressedPointFlag::Positive => Ok(AffineG2::new_unchecked(x, y)),
        CompressedPointFlag::Negative => Ok(AffineG2::new_unchecked(x, neg_y)),
        _ => Err(Error::InvalidPoint),
    }
}

pub(crate) fn uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 128 {
        return Err(Error::InvalidXLength);
    }

    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_slice(x1_bytes).map_err(Error::Field)?;
    let x0 = Fq::from_slice(x0_bytes).map_err(Error::Field)?;
    let y1 = Fq::from_slice(y1_bytes).map_err(Error::Field)?;
    let y0 = Fq::from_slice(y0_bytes).map_err(Error::Field)?;

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    AffineG2::new(x, y).map_err(Error::Group)
}
