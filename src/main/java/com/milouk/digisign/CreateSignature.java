package com.milouk.digisign;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Enumeration;

public class CreateSignature implements SignatureInterface {
	private static PrivateKey privateKey;
	private static Certificate certificate;

	boolean signPdf(File pdfFile, File signedPdfFile) {

		try (FileInputStream fis1 = new FileInputStream(pdfFile);
				FileOutputStream fos = new FileOutputStream(signedPdfFile);
				FileInputStream fis = new FileInputStream(signedPdfFile);
				FileOutputStream fos2 = new FileOutputStream(signedPdfFile);
				PDDocument doc = PDDocument.load(pdfFile)) {
			int readCount;
			byte[] buffer = new byte[8 * 1024];
			while ((readCount = fis1.read(buffer)) != -1) {
				fos.write(buffer, 0, readCount);
			}

			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setName("NAME");
			signature.setLocation("LOCATION");
			signature.setReason("REASON");
			signature.setContactInfo("CONTACT INFO");
			signature.setSignDate(Calendar.getInstance());
			doc.addSignature(signature, this);
			doc.saveIncremental(fos2);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] sign(InputStream is) throws IOException {
		try {
			BouncyCastleProvider BC = new BouncyCastleProvider();
			Store<?> certStore = new JcaCertStore(Collections.singletonList(certificate));

			CMSTypedDataInputStream input = new CMSTypedDataInputStream(is);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BC).build(privateKey);

			gen.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
							.build(sha512Signer, new X509CertificateHolder(certificate.getEncoded())));
			gen.addCertificates(certStore);
			CMSSignedData signedData = gen.generate(input, false);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ASN1OutputStream dos = ASN1OutputStream.create(baos, ASN1Encoding.DER);
			dos.writeObject(signedData.toASN1Structure());
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException {

		String key = "";
		String pass = "";
		String input = "";
		String output = "";
		Options options = new Options();
		options.addRequiredOption("k", "key", true, "PKCS12 KeyStore");
		options.addRequiredOption("p", "password", true, "KeyStore Password");
		options.addRequiredOption("i", "input", true, "Input Pdf File");
		options.addRequiredOption("o", "output", true, "Signed Pdf File");
		options.addOption(Option.builder("h").longOpt("help").build());
		String header = "\nDigitally Sign your PDF Documents\n\n";
		String footer = "\nPlease report issues at http://github.com/milouk/DigiSign/issues";
		HelpFormatter formatter = new HelpFormatter();

		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);
			if (cmd.hasOption("h") || cmd.getArgs().length == 0) {
				formatter.printHelp("Digi Sign", header, options, footer, true);
				System.exit(0);
			}
			if (cmd.hasOption("k")) {
				key = cmd.getOptionValue("k");
			}
			if (cmd.hasOption("p")) {
				pass = cmd.getOptionValue("p");
			}
			if (cmd.hasOption("i")) {
				input = cmd.getOptionValue("input");
			}
			if (cmd.hasOption("o")) {
				output = cmd.getOptionValue("o");
			}
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			formatter.printHelp("Digi Sign", header, options, footer, true);
			System.exit(0);
		}

		char[] password = pass.toCharArray();

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(key), password);

		Enumeration<String> aliases = keystore.aliases();
		String alias;
		if (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
		} else {
			throw new KeyStoreException("Keystore is empty");
		}
		privateKey = (PrivateKey) keystore.getKey(alias, password);
		Certificate[] certificateChain = keystore.getCertificateChain(alias);
		certificate = certificateChain[0];

		File inFile = new File(input);
		File outFile = new File(output);
		new CreateSignature().signPdf(inFile, outFile);
	}
}

class CMSTypedDataInputStream implements CMSTypedData {
	InputStream in;

	public CMSTypedDataInputStream(InputStream is) {
		in = is;
	}

	@Override
	public ASN1ObjectIdentifier getContentType() {
		return PKCSObjectIdentifiers.data;
	}

	@Override
	public Object getContent() {
		return in;
	}

	@Override
	public void write(OutputStream out) throws IOException, CMSException {
		byte[] buffer = new byte[8 * 1024];
		int read;
		while ((read = in.read(buffer)) != -1) {
			out.write(buffer, 0, read);
		}
		in.close();
	}
}
