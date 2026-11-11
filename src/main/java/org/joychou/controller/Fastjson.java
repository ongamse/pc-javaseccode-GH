package org.joychou.controller;

import org.joychou.util.WebUtils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
@RequestMapping("/fastjson")
public class Fastjson {

    @RequestMapping(value = "/deserialize", method = {RequestMethod.POST})
    @ResponseBody
    public String Deserialize(@RequestBody String params) {
        // 如果Content-Type不设置application/json格式，post数据会被url编码
        try {
            // 将post提交的string转换为json
            JSONObject ob = JSON.parseObject(params);
            return WebUtils.htmlEscape(String.valueOf(ob.get("name")));
        } catch (Exception e) {
            return WebUtils.htmlEscape(e.toString());
        }
    }

    // NOTE: A demo main() embedding a base64-encoded TemplatesImpl exploit
    // payload (fastjson deserialization gadget) was removed from this file.
    // It was a non-secret exploit sample, not a credential.
}
