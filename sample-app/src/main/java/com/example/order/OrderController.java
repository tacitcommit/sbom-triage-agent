package com.example.order;

// 데모용 샘플 코드. 어떤 의존성은 실제로 호출하고(도달 가능), 어떤 것은 선언만 해 둔다(도달 불가).
//  - log4j-core   : 사용자 입력을 그대로 로그에 남긴다 → 도달 가능
//  - snakeyaml    : 요청 본문을 Yaml.load 로 읽는다 → 도달 가능
//  - jackson      : ObjectMapper 를 쓰지만 default typing 은 켜지 않는다 → 해당 CVE 의 조건 미충족
//  - commons-text : pom 에만 있고 코드에서 쓰지 않는다 → 도달 불가

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.util.Map;

public class OrderController {

    private static final Logger log = LogManager.getLogger(OrderController.class);
    private final ObjectMapper mapper = new ObjectMapper();

    public String createOrder(String userAgent, String body) throws Exception {
        log.info("order request from {}", userAgent);
        Map<String, Object> order = new Yaml().load(body);
        return mapper.writeValueAsString(order);
    }
}
