//! Base Types defined in Part 2, Section 5 "Base Types"
use crate::{
    errors::UnmarshalError,
    marshal::{Limits, MarshalFixed, Unmarshal, UnmarshalFixed, pop_array},
};

impl MarshalFixed for () {
    const SIZE: usize = 0;
    type Array = [u8; 0];
    #[inline]
    fn marshal_fixed(&self, _: &mut [u8; 0]) {}
}
impl UnmarshalFixed for () {
    #[inline]
    fn unmarshal_fixed<L: Limits>(_: &[u8; 0]) -> Result<Self, UnmarshalError> {
        Ok(())
    }
}

impl MarshalFixed for bool {
    const SIZE: usize = 1;
    type Array = [u8; 1];
    #[inline]
    fn marshal_fixed(&self, arr: &mut [u8; 1]) {
        *arr = [u8::from(*self)];
    }
}
impl UnmarshalFixed for bool {
    #[inline]
    fn unmarshal_fixed<L: Limits>(arr: &[u8; 1]) -> Result<Self, UnmarshalError> {
        match *arr {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(UnmarshalError),
        }
    }
}

/// Implement [`MarshalFixed`] and [`UnmarshalFixed`] for integer types
macro_rules! impl_ints { ($($T: ty),+) => { $(
    impl MarshalFixed for $T {
        const SIZE: usize = size_of::<Self>();
        type Array = [u8; size_of::<Self>()];
        #[inline]
        fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
            *arr = self.to_be_bytes();
        }
    }
    impl UnmarshalFixed for $T {
        #[inline]
        fn unmarshal_fixed<L: Limits>(arr: &[u8; Self::SIZE]) -> Result<Self, UnmarshalError> {
            Ok(Self::from_be_bytes(*arr))
        }
    }
)+ } }
impl_ints!(u8, u16, u32, u64, i8, i16, i32, i64);

impl<const N: usize> MarshalFixed for &[u8; N] {
    const SIZE: usize = N;
    type Array = [u8; N];
    #[inline]
    fn marshal_fixed(&self, arr: &mut [u8; N]) {
        *arr = **self;
    }
}
impl<'a, 's: 'a, const N: usize> Unmarshal<'s> for &'a [u8; N] {
    #[inline]
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        *self = pop_array(&mut buf)?;
        Ok(buf)
    }

    fn unmarshal2<L: Limits>(&mut self, buf: &mut &'s [u8]) -> Result<(), UnmarshalError> {
        *self = pop_array(buf)?;
        Ok(())
    }

    fn unmarshal3<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<usize, UnmarshalError> {
        *self = pop_array(&mut buf)?;
        Ok(N)
    }
}
