package dev.krillin.bifrost.core.mapping;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import javax.xml.parsers.*;
import javax.xml.XMLConstants;
import org.w3c.dom.*;

/** Independent XLSX locator verification only; does not interpret a vendor memory map. */
final class XlsxEvidence {
    private XlsxEvidence(){}
    private static Document xml(byte[] bytes) throws Exception {
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        f.setFeature("http://xml.org/sax/features/external-general-entities",false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
    }
    static boolean hasCell(Path path,String sheet,String cell) throws Exception {
        Map<String,byte[]> entries=new HashMap<>();long total=0;
        try(ZipInputStream in=new ZipInputStream(Files.newInputStream(path))){
            ZipEntry e;while((e=in.getNextEntry())!=null){
                if(e.isDirectory())continue;
                byte[] data=in.readNBytes(4*1024*1024+1);total+=data.length;
                MappingJson.require(data.length<=4*1024*1024&&total<=16*1024*1024&&entries.size()<4096,"evidence.xlsx-limit");
                MappingJson.require(entries.putIfAbsent(e.getName(),data)==null,"evidence.xlsx-duplicate");
            }
        }
        var wb=xml(Objects.requireNonNull(entries.get("xl/workbook.xml")));
        var rels=xml(Objects.requireNonNull(entries.get("xl/_rels/workbook.xml.rels")));
        String rid=null;NodeList sheets=wb.getElementsByTagNameNS("*","sheet");
        for(int i=0;i<sheets.getLength();i++){Element e=(Element)sheets.item(i);if(e.getAttribute("name").equals(sheet))rid=e.getAttributeNS("http://schemas.openxmlformats.org/officeDocument/2006/relationships","id");}
        if(rid==null)return false;String target=null;NodeList relations=rels.getElementsByTagNameNS("*","Relationship");
        for(int i=0;i<relations.getLength();i++){Element e=(Element)relations.item(i);if(e.getAttribute("Id").equals(rid)&&!e.getAttribute("TargetMode").equals("External"))target=e.getAttribute("Target");}
        if(target==null)return false;
        String name=target.startsWith("/")?target.substring(1):Path.of("xl").resolve(target).normalize().toString().replace('\\','/');
        MappingJson.require(name.startsWith("xl/")&&!name.contains("../"),"evidence.xlsx-target");
        var doc=xml(Objects.requireNonNull(entries.get(name)));NodeList cells=doc.getElementsByTagNameNS("*","c");
        for(int i=0;i<cells.getLength();i++)if(((Element)cells.item(i)).getAttribute("r").equals(cell))return true;
        return false;
    }
}
