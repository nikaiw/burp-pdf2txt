package com.pdf2txt;
import org.icepdf.core.exceptions.PDFException;
import org.icepdf.core.exceptions.PDFSecurityException;
import org.icepdf.core.pobjects.Document;
import org.icepdf.core.pobjects.graphics.text.LineText;
import org.icepdf.core.pobjects.graphics.text.PageText;
import org.icepdf.core.pobjects.graphics.text.WordText;
import org.icepdf.ri.util.FontPropertiesManager;
import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class PdfParser {
    public static void main(String[] args) throws IllegalAccessException, InstantiationException {
        FontPropertiesManager.getInstance().loadOrReadSystemFonts();
        String filePath = args[0];
        Document document = new Document();
        try {
            document.setFile(filePath);
        } catch (PDFException ex) {
            System.out.println("Error parsing PDF document " + ex);
        } catch (PDFSecurityException ex) {
            System.out.println("Error encryption not supported " + ex);
        } catch (FileNotFoundException ex) {
            System.out.println("Error file not found " + ex);
        } catch (IOException ex) {
            System.out.println("Error handling PDF document " + ex);
        }

        try {
            BufferedOutputStream out = new BufferedOutputStream(System.out);
            for (int pageNumber = 0, max = document.getNumberOfPages();
            pageNumber < max; pageNumber++) {
                PageText pageText = document.getPageText(pageNumber);
                if (pageText != null && pageText.getPageLines() != null) {
                    ArrayList<LineText> pageLines = pageText.getPageLines();

                    for (LineText lineText : pageLines) {
                        List<WordText> mylist = lineText.getWords();
                        for (WordText e: mylist) {
                            System.out.print(e.getText());

                        }
                    }
                }
            }

            // close the writer
            out.flush();
            out.close();
        } catch (IOException ex) {
            System.out.println("Error writing to file " + ex);
        } catch (InterruptedException ex) {
            System.out.println("Error paring page " + ex);
        }
        // clean up resources
        document.dispose();
        }

    public static String parse(byte[] pdf) throws IllegalAccessException, InstantiationException {
        StringBuffer sb = new StringBuffer();
        FontPropertiesManager.getInstance().loadOrReadSystemFonts();
        Document document = new Document();
        try {
            document.setByteArray(pdf, 0 ,pdf.length,"");
            sb.append("Author: " + document.getInfo().getAuthor() + "\n");
            sb.append("Creator: " + document.getInfo().getCreator() + "\n");
            sb.append("Subject: " + document.getInfo().getSubject() + "\n");
            sb.append("Producer: " + document.getInfo().getProducer() + "\n");
            sb.append("Keyword: " + document.getInfo().getKeywords() + "\n");
            sb.append("Title: " + document.getInfo().getTitle() + "\n");
            sb.append("Creation Date: " + document.getInfo().getCreationDate() + "\n");
            sb.append("Modification Date: " + document.getInfo().getModDate().asLocalDateTime().format(DateTimeFormatter.ISO_TIME) + "\n");
            sb.append("Trapping: " + document.getInfo().getTrappingInformation() + "\n\n");
            for (int pageNumber = 0, max = document.getNumberOfPages();
                 pageNumber < max; pageNumber++) {
                PageText pageText = document.getPageText(pageNumber);
                if (pageText != null && pageText.getPageLines() != null) {
                    ArrayList<LineText> pageLines = pageText.getPageLines();
                    for (LineText lineText : pageLines) {
                        List<WordText> mylist = lineText.getWords();
                        for (WordText e: mylist) {
                            sb.append(e.getText());
                        }
                    }
                }
            }
        } catch (IOException ex) {
            System.out.println("Error writing to file " + ex);
        } catch (InterruptedException ex) {
            System.out.println("Error paring page " + ex);
        } catch (PDFException ex) {
            System.out.println("Error parsing PDF document " + ex);
        } catch (PDFSecurityException ex) {
            System.out.println("Error encryption not supported " + ex);
        }
        // clean up resources
        document.dispose();
        return sb.toString();
    }
}
