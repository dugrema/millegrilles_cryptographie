pub mod mapstringepochseconds {
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Serializer, Deserializer};
    use serde::de::Error as DeError;
    use serde::ser::SerializeMap;

    pub fn serialize<S>(value: &HashMap<String, DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut map_serializer = serializer.serialize_map(Some(value.len()))?;
        for (k, v) in value {
            map_serializer.serialize_key(k)?;
            map_serializer.serialize_value(&v.timestamp())?;
        }
        map_serializer.end()
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<HashMap<String, DateTime<Utc>>, D::Error>
        where D: Deserializer<'de>,
    {
        let s: HashMap<String, i64> = HashMap::deserialize(deserializer)?;
        let mut map_dates = HashMap::new();

        for (k, v) in s {
            let date = match DateTime::from_timestamp(v, 0) {
                Some(inner) => inner,
                None => Err(D::Error::custom("Date invalide"))?
            };
            map_dates.insert(k, date);
        }

        Ok(map_dates)
    }
}

pub mod optionmapstringepochseconds {
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Serializer, Deserializer};
    use serde::de::Error as DeError;
    use serde::ser::SerializeMap;

    pub fn serialize<S>(value: &Option<HashMap<String, DateTime<Utc>>>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match value {
            Some(value) => {
                let mut map_serializer = serializer.serialize_map(Some(value.len()))?;
                for (k, v) in value {
                    map_serializer.serialize_key(k)?;
                    map_serializer.serialize_value(&v.timestamp())?;
                }
                map_serializer.end()
            },
            None => serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<Option<HashMap<String, DateTime<Utc>>>, D::Error>
        where D: Deserializer<'de>,
    {
        let s: Option<HashMap<String, i64>> = Option::deserialize(deserializer)?;
        match s {
            Some(inner) => {
                // let s: HashMap<String, i64> = HashMap::deserialize(deserializer)?;
                let mut map_dates = HashMap::new();

                for (k, v) in inner {
                    let date = match DateTime::from_timestamp(v, 0) {
                        Some(inner) => inner,
                        None => Err(D::Error::custom("Date invalide"))?
                    };
                    map_dates.insert(k, date);
                }

                Ok(Some(map_dates))
            },
            None => Ok(None)
        }
    }
}

#[cfg(test)]
mod messages_structs_tests {
    use std::collections::HashMap;
    use chrono::{DateTime, Utc};
    use super::*;
    use log::info;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use crate::messages_structs::{MessageKind, MessageMilleGrillesRefDefault};

    #[derive(Serialize, Deserialize)]
    struct MapStringDate {
        #[serde(with="mapstringepochseconds")]
        map_dates: HashMap<String, DateTime<Utc>>,
        #[serde(with="optionmapstringepochseconds")]
        map_dates_option: Option<HashMap<String, DateTime<Utc>>>,
        #[serde(with="optionmapstringepochseconds")]
        map_dates_option2: Option<HashMap<String, DateTime<Utc>>>
    }

    #[test_log::test]
    fn test_mod_mapstringepochseconds() {

        let mut map_dates = HashMap::new();
        let now = Utc::now();
        map_dates.insert("Date 1".to_string(), now);

        let mut map_dates_option = HashMap::new();
        map_dates_option.insert("Date 2".to_string(), now);

        let map_dates_1 = MapStringDate {
            map_dates,
            map_dates_option: Some(map_dates_option),
            map_dates_option2: None
        };

        let string_map = serde_json::to_string(&map_dates_1).unwrap();
        info!("String map :\n{}", string_map);
        let map_deser: MapStringDate = serde_json::from_str(string_map.as_str()).unwrap();

        let map_date_value = map_deser.map_dates.get("Date 1").unwrap();
        info!("Date deserialisee : {:?}", map_date_value);

        let map_date_option = map_deser.map_dates_option.unwrap();
        let map_date_option_value = map_date_option.get("Date 2").unwrap();

        assert_eq!(now.timestamp(), map_date_value.timestamp());
        assert_eq!(now.timestamp(), map_date_option_value.timestamp());
        assert!(map_deser.map_dates_option2.is_none());
    }

}
