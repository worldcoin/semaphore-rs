pub const fn get_supported_depth_count() -> usize {
    let mut res = 0;
    #[cfg(feature = "depth_16")]
    {
        res += 1;
    }
    #[cfg(feature = "depth_20")]
    {
        res += 1;
    }
    #[cfg(feature = "depth_30")]
    {
        res += 1;
    }
    res
}

#[allow(unused_assignments)]
const fn gen_supported_depths() -> [usize; get_supported_depth_count()] {
    let mut res = [0; get_supported_depth_count()];
    let mut i = 0;
    #[cfg(feature = "depth_16")]
    {
        res[i] = 16;
        i += 1;
    }
    #[cfg(feature = "depth_20")]
    {
        res[i] = 20;
        i += 1;
    }
    #[cfg(feature = "depth_30")]
    {
        res[i] = 30;
        i += 1;
    }
    res
}

static SUPPORTED_DEPTHS: [usize; get_supported_depth_count()] = gen_supported_depths();

pub fn get_supported_depths() -> &'static [usize] {
    &SUPPORTED_DEPTHS
}

pub const fn is_depth_supported(depth: usize) -> bool {
    #[cfg(feature = "depth_16")]
    {
        if depth == 16 {
            return true;
        }
    }
    #[cfg(feature = "depth_20")]
    {
        if depth == 20 {
            return true;
        }
    }
    #[cfg(feature = "depth_30")]
    {
        if depth == 30 {
            return true;
        }
    }
    false
}

#[allow(unused_assignments)]
pub const fn get_depth_index(depth: usize) -> Option<usize> {
    let mut i = 0;
    #[cfg(feature = "depth_16")]
    {
        if depth == 16 {
            return Some(i);
        }
        i += 1;
    }
    #[cfg(feature = "depth_20")]
    {
        if depth == 20 {
            return Some(i);
        }
        i += 1;
    }
    #[cfg(feature = "depth_30")]
    {
        if depth == 30 {
            return Some(i);
        }
        i += 1;
    }
    None
}
