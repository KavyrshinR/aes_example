package ru.kavyrshin.aesexample

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.android.synthetic.main.activity_main.*
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {

    companion object {
        const val ALGORITHM = "AES/CBC/PKCS7PADDING"

        const val ALIAS = "Whatever"
    }

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (keyStore.containsAlias(ALIAS).not()) {
            generateAndSaveAesKey()
        }

        buttonEncrypt.setOnClickListener {
            val openText = editTextOpentext.text.toString()
            val cipherText = encryptMessage(openText.toByteArray(Charsets.UTF_8))

//            Log.d("myLogs", "iv + cipherText ${Arrays.toString(cipherText)}")

            val cipherString = String(Base64.encode(cipherText, Base64.DEFAULT), Charsets.UTF_8)
            editTextCiphertext.setText(cipherString)
        }

        buttonDecrypt.setOnClickListener {
            val cipherString = editTextCiphertext.text.toString()
            val cipherText = Base64.decode(cipherString.toByteArray(Charsets.UTF_8), Base64.DEFAULT)

//            Log.d("myLogs", "cipherText.length ${cipherText.size}")
            val openText = decryptMessage(cipherText)

            editTextOpentext.setText(String(openText, Charsets.UTF_8))
        }
    }

    private fun generateIvSpec(blockSize: Int): IvParameterSpec {
        val random = SecureRandom()
        val ivRandomBytes = ByteArray(blockSize)
        random.nextBytes(ivRandomBytes)
        return IvParameterSpec(ivRandomBytes)
    }

    private fun encryptMessage(openText: ByteArray): ByteArray {
        val entry = keyStore.getEntry(ALIAS, null) as KeyStore.SecretKeyEntry
        val secretKey = entry.secretKey

        val cipher = Cipher.getInstance(ALGORITHM)
        //val ivSpec = generateIvSpec(cipher.blockSize)
        //Работая внутри keyStore он не дает подавать свой iv
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

//        Log.d("myLogs", "encryptMessage: IV from cipher ${Arrays.toString(cipher.iv)}")

        val ciphertext: ByteArray = cipher.doFinal(openText)

//        Log.d("myLogs", "cipherText.length ${ciphertext.size}")

        return cipher.iv + ciphertext
    }

    private fun decryptMessage(cipherText: ByteArray): ByteArray {
        val entry = keyStore.getEntry(ALIAS, null) as KeyStore.SecretKeyEntry
        val secretKey = entry.secretKey

        val cipher = Cipher.getInstance(ALGORITHM)

        val ivBytes = cipherText.copyOfRange(0, cipher.blockSize)
        val ivSpec = IvParameterSpec(ivBytes)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

//        Log.d("myLogs", "decryptMessage: blockSize ${cipher.blockSize}")
//        Log.d("myLogs", "decryptMessage: IV ${Arrays.toString(cipher.iv)}")

        val opentext: ByteArray = cipher.doFinal(cipherText, cipher.blockSize, cipherText.size - cipher.blockSize)

        return opentext
    }

    private fun generateAndSaveAesKey() {
        val aesSpec: KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                .build()

        val keygen = KeyGenerator.getInstance("AES", "AndroidKeyStore")
        keygen.init(aesSpec)
        keygen.generateKey()
    }
}