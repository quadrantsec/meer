--
-- Table structure for table `reference_data`
--

DROP TABLE IF EXISTS `reference_data`;

CREATE TABLE `reference_data` (
  `sid` bigint(20) NOT NULL,
  `ref_type` varchar(10) NOT NULL,
  `ref_url` varchar(255) NOT NULL,
  PRIMARY KEY (`sid`,`ref_type`,`ref_url`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
