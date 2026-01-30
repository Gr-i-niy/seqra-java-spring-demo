package org.example.util;

import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class XmlParser {

    private XmlParser() {}

    // VULNERABLE: No XXE protection
    public static Map<String, String> parseUnsafe(String xmlContent) throws Exception {
        Map<String, String> map = new HashMap<>();
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
        SAXReader reader = new SAXReader();
        Document document = reader.read(inputStream);
        Element root = document.getRootElement();
        List<Element> elements = root.elements();
        for (Element e : elements) {
            map.put(e.getName(), e.getText());
        }
        inputStream.close();
        return map;
    }

    // SECURE: XXE protection enabled
    public static Map<String, String> parseSafe(String xmlContent) throws Exception {
        Map<String, String> map = new HashMap<>();
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Document document = reader.read(inputStream);
        Element root = document.getRootElement();
        List<Element> elements = root.elements();
        for (Element e : elements) {
            map.put(e.getName(), e.getText());
        }
        inputStream.close();
        return map;
    }
}
