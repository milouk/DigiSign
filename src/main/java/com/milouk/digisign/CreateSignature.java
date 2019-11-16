package com.milouk.digisign;

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
			doc.saveIncremental(fis, fos);
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
		char[] password = "1234".toCharArray();

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream("keyStore.p12"), password);

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

		File inFile = new File("unsigned.pdf");
		File outFile = new File("signed.pdf");
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
