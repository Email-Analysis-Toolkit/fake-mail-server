#![allow(dead_code)]

use std::convert::TryFrom;

use imap_codec::types::core::Tag;

struct Predictor {
    strategy: Strategy,
}

enum Strategy {
    Evolution,
}

struct PredictorIter<'a> {
    predictor: &'a Predictor,
    current_tag: Tag<'a>,
}

impl<'a> Iterator for PredictorIter<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let predicted_tag = self.predictor.predict(&self.current_tag);
        self.current_tag = predicted_tag;
        Some(self.current_tag.clone())
    }
}

impl Predictor {
    pub fn with_strategy(strategy: Strategy) -> Predictor {
        Predictor { strategy }
    }

    pub fn predict(&self, current_tag: &Tag) -> Tag {
        let current_tag = current_tag.inner().to_string();

        match self.strategy {
            Strategy::Evolution => {
                let (current_prefix, current_index) = current_tag.split_at(1);

                let predicted_prefix = current_prefix;
                let predicted_index = current_index.parse::<u32>().unwrap() + 1;

                let predicted_tag = format!("{}{:05}", predicted_prefix, predicted_index);
                Tag::try_from(predicted_tag).unwrap()
            }
        }
    }

    pub fn predict_iter(&self, current_tag: Tag<'static>) -> PredictorIter {
        PredictorIter {
            predictor: self,
            current_tag,
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use imap_codec::types::core::Tag;

    use super::{Predictor, Strategy};

    #[test]
    fn test_predictor_evolution() {
        let predictor = Predictor::with_strategy(Strategy::Evolution);
        let mut iter = predictor.predict_iter(Tag::try_from("A00021").unwrap());

        assert_eq!(iter.next(), Some(Tag::try_from("A00022").unwrap()));
        assert_eq!(iter.next(), Some(Tag::try_from("A00023").unwrap()));
        assert_eq!(iter.next(), Some(Tag::try_from("A00024").unwrap()));
        assert_eq!(iter.next(), Some(Tag::try_from("A00025").unwrap()));
    }
}
