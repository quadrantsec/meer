
DROP TABLE IF EXISTS `drop_list`;
CREATE TABLE `drop_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT, 
  `timestamp`	DATETIME NOT NULL, 
  `ip`		VARCHAR(64) NOT NULL,
  `sid`         BIGINT(20) NOT NULL, 
  KEY `id` (`id`),
  INDEX `ip` (`ip`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

