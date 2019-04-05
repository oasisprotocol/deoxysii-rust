/// Size of the Deoxys-II-256-128 key in bytes.
pub const KEY_SIZE: usize = 32;
/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 15;
/// Size of the authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the block used in the block cipher in bytes.
const BLOCK_SIZE: usize = 16;
/// Number of rounds used in the block cipher.
const ROUNDS: usize = 16;
/// Size of the tweak in bytes.
const TWEAK_SIZE: usize = 16;
/// Size of the sub-tweak key in bytes.
const STK_SIZE: usize = 16;
/// Number of sub-tweak keys.
const STK_COUNT: usize = ROUNDS + 1;

/// Block prefixes.
const PREFIX_SHIFT: usize = 4;
const PREFIX_AD_BLOCK: u8 = 0b0010;
const PREFIX_AD_FINAL: u8 = 0b0110;
const PREFIX_MSG_BLOCK: u8 = 0b0000;
const PREFIX_MSG_FINAL: u8 = 0b0100;
const PREFIX_TAG: u8 = 0b0001;

/// Hack that enables us to have __m128i vector constants.
#[repr(C)]
union u8x16 {
    v: __m128i,
    b: [u8; 16],
}

/// Generates a `__m128i` vector from given `u8` components.
/// The order of components is lowest to highest.
///
/// Note that the order of components is the reverse of `_mm_set_epi8`,
/// which goes from highest component to lowest!
/// Also, we use `u8` components, while `_mm_set_epi8` uses `i8` components.
///
/// This macro exists only because it's not possible to use `_mm_set_epi8`
/// to produce constant vectors.
macro_rules! m128i_vec {
    ( $( $x:expr ),* ) => { unsafe { (u8x16 { b: [$($x,)*] } ).v } };
}

/// Byte shuffle order for the h() function, apply it with `_mm_shuffle_epi8`.
const H_SHUFFLE: __m128i = m128i_vec![7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6];

/// This shuffle order converts the lower half of the vector from little-endian
/// to big-endian and moves it to the upper half, clearing the lower half to
/// zero (the 0x80 constants set the corresponding byte to zero).
const LE2BE_SHUFFLE: __m128i =
    m128i_vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 7, 6, 5, 4, 3, 2, 1, 0];
