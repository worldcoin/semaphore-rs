use crate::merkle_tree::Branch;

pub fn leaf_to_node(leaf: usize) -> usize {
    leaf + (leaf + 1).next_power_of_two()
}

#[allow(unused)]
pub fn index_to_leaf(index: usize) -> usize {
    let next = (index + 1).next_power_of_two();
    let prev = next >> 1;
    index - prev
}

pub fn parent(i: usize) -> usize {
    if i.is_power_of_two() {
        return i << 1;
    }

    let prev_pow = i.next_power_of_two() >> 1;
    let shifted = i - prev_pow;
    let shifted_parent = shifted >> 1;

    shifted_parent + prev_pow
}

pub fn children(i: usize) -> Option<(usize, usize)> {
    if i <= 1 {
        return None;
    }

    if i.is_power_of_two() {
        let left = i >> 1;
        let right = i + 1;

        Some((left, right))
    } else {
        let next_power_of_two = i.next_power_of_two();
        let prev_power_of_two = next_power_of_two >> 1;
        let shifted = i - prev_power_of_two;

        let left = shifted * 2;
        let right = shifted * 2 + 1;

        let left = left + prev_power_of_two;
        let right = right + prev_power_of_two;

        if left >= next_power_of_two {
            return None;
        }

        Some((left, right))
    }
}

pub fn parent_and_sibling(i: usize) -> (usize, Branch<usize>) {
    let parent = parent(i);

    let sibling = if parent.is_power_of_two() {
        if i == parent + 1 {
            Branch::Left(parent >> 1)
        } else {
            Branch::Right(parent + 1)
        }
    } else {
        let prev_power_of_two = i.next_power_of_two() >> 1;
        let shifted = i - prev_power_of_two;

        if shifted % 2 == 0 {
            Branch::Right(i + 1)
        } else {
            Branch::Left(i - 1)
        }
    };

    (parent, sibling)
}

#[allow(unused)]
pub fn sibling(i: usize) -> Branch<usize> {
    parent_and_sibling(i).1
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(0, 1)]
    #[test_case(1, 3)]
    #[test_case(2, 6)]
    #[test_case(3, 7)]
    #[test_case(7, 15)]
    #[test_case(8, 24)]
    fn leaf_index_conversion(leaf: usize, index: usize) {
        let actual_index = leaf_to_node(leaf);

        assert_eq!(actual_index, index);

        let actual_leaf = index_to_leaf(index);
        assert_eq!(actual_leaf, leaf);
    }

    #[test_case(1 => 2)]
    #[test_case(2 => 4)]
    #[test_case(4 => 8)]
    #[test_case(3 => 2)]
    #[test_case(6 => 5)]
    #[test_case(7 => 5)]
    #[test_case(5 => 4)]
    fn parent_of(i: usize) -> usize {
        parent(i)
    }

    #[test_case(0 => None)]
    #[test_case(1 => None)]
    #[test_case(3 => None)]
    #[test_case(6 => None)]
    #[test_case(7 => None)]
    #[test_case(12 => None)]
    #[test_case(13 => None)]
    #[test_case(14 => None)]
    #[test_case(15 => None)]
    #[test_case(2 => Some((1, 3)))]
    #[test_case(4 => Some((2, 5)))]
    #[test_case(8 => Some((4, 9)))]
    #[test_case(9 => Some((10, 11)))]
    #[test_case(11 => Some((14, 15)))]
    fn children_of(i: usize) -> Option<(usize, usize)> {
        children(i)
    }

    #[test_case(1 => Branch::Right(3))]
    #[test_case(3 => Branch::Left(1))]
    #[test_case(2 => Branch::Right(5))]
    #[test_case(12 => Branch::Right(13))]
    #[test_case(11 => Branch::Left(10))]
    fn sibling_of(i: usize) -> Branch<usize> {
        sibling(i)
    }
}
