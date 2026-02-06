SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS `arp_info`  (
                                           `id` int NOT NULL AUTO_INCREMENT,
                                           `ipv4` char(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'IPv4地址(点分十进制)',
    `mac` char(17) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'MAC地址',
    `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    PRIMARY KEY (`id`) USING BTREE
    ) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'arp信息表' ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
