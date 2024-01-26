package ru.kavyrshin.aesexample

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.schedulers.Schedulers
import kotlinx.android.synthetic.main.activity_user_key.*
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val ALGORITHM = "AES/CBC/NoPadding"
const val SALT = "ab12f5ac56666666"

class UserKeyActivity : AppCompatActivity() {

    private val argon2Kt = Argon2Kt()
    private val compositeDisposable = CompositeDisposable()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_user_key)

        buttonEncrypt.setOnClickListener {
            val random = SecureRandom()
            val openTextBeforePad = editTextOpentext.text.toString().toByteArray(Charsets.UTF_8)
//            Log.d("myLogs", "utf-8 bytes  ${openTextBeforePad.contentToString()}")
//            Log.d("myLogs", "utf-8 length ${openTextBeforePad.size}")

            val paddingNeededSize = 16 - (openTextBeforePad.size % 16)
            val noPadding = ByteArray(paddingNeededSize).also {
                random.nextBytes(it)
            }
            val openText = openTextBeforePad + noPadding
//            Log.d("myLogs", "openTextSize ${openText.size}; openText ${openText.contentToString()}")

            val key = editTextKey.text.toString()
            val salt = editTextSalt.text.toString().takeIf { it.isNotBlank() } ?: SALT

            compositeDisposable.add(generateAesKey(key, salt)
                .subscribeOn(Schedulers.computation())
                .observeOn(AndroidSchedulers.mainThread())
                .doOnSubscribe { progressBar.visibility = View.VISIBLE }
                .doFinally { progressBar.visibility = View.GONE }
                .subscribe({ secretKey ->
                    val cipherText = encryptMessage(
                        openText,
                        secretKey = secretKey
                    )

//                    Log.d("myLogs", "iv + cipherText ${Arrays.toString(cipherText)}")

                    val cipherString = String(Base64.encode(cipherText, Base64.DEFAULT), Charsets.UTF_8)
                    editTextCiphertext.setText(cipherString)
                },{
                    it.printStackTrace()
                })
            )
        }

        buttonDecrypt.setOnClickListener {
            val cipherString = editTextCiphertext.text.toString()

            val key = editTextKey.text.toString()
            val salt = editTextSalt.text.toString().takeIf { it.isNotBlank() } ?: SALT

            compositeDisposable.add(generateAesKey(key, salt)
                .subscribeOn(Schedulers.computation())
                .observeOn(AndroidSchedulers.mainThread())
                .doOnSubscribe { progressBar.visibility = View.VISIBLE }
                .doFinally { progressBar.visibility = View.GONE }
                .map { secretKey ->
                    val cipherText = Base64.decode(cipherString.toByteArray(Charsets.UTF_8), Base64.DEFAULT)
                    cipherText to secretKey
                }
                .map { (cipherText, secretKey) ->
//                    Log.d("myLogs", "cipherText.length ${cipherText.size}")
                    decryptMessage(cipherText, secretKey)
                }
                .subscribe({ plainText ->
                    editTextOpentext.setText(String(plainText, Charsets.UTF_8))
                },{
                    Toast.makeText(this, it.javaClass.name, Toast.LENGTH_LONG).show()
                    it.printStackTrace()
                })
            )
        }
    }

    private fun generateIvSpec(blockSize: Int): IvParameterSpec {
        val random = SecureRandom()
        val ivRandomBytes = ByteArray(blockSize)
        random.nextBytes(ivRandomBytes)
        return IvParameterSpec(ivRandomBytes)
    }

    private fun encryptMessage(openText: ByteArray, secretKey: SecretKey): ByteArray {

        val cipher = Cipher.getInstance(ALGORITHM)
        val ivSpec = generateIvSpec(cipher.blockSize)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

//        Log.d("myLogs", "encryptMessage: IV from cipher ${Arrays.toString(cipher.iv)}")

        val ciphertext: ByteArray = cipher.doFinal(openText)

//        Log.d("myLogs", "cipherText.length ${ciphertext.size}")

        return cipher.iv + ciphertext
    }

    @Throws(GeneralSecurityException::class)
    private fun decryptMessage(cipherText: ByteArray, secretKey: SecretKey): ByteArray {

        val cipher = Cipher.getInstance(ALGORITHM)

        val ivBytes = cipherText.copyOfRange(0, cipher.blockSize)
        val ivSpec = IvParameterSpec(ivBytes)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

//        Log.d("myLogs", "decryptMessage: blockSize ${cipher.blockSize}")
//        Log.d("myLogs", "decryptMessage: IV ${Arrays.toString(cipher.iv)}")

        return cipher.doFinal(cipherText, cipher.blockSize, cipherText.size - cipher.blockSize)
    }

    private fun generateAesKey(userKey: String, salt: String): Single<SecretKey> { //TODO: Почему то отрабытывает быстрее чем в sample с теми же параметрами
//        val saltByteArray = Argon2KtUtils.decodeAsHex(salt)
        val saltByteArray = salt.toByteArray(Charsets.US_ASCII)
//        Log.d("myLogs", "saltByteArray: ${saltByteArray.contentToString()}")
        return Single.fromCallable {
            val result = argon2Kt.hash(
                mode = Argon2Mode.ARGON2_ID,
                password = userKey.toByteArray(),
                salt = saltByteArray,
                tCostInIterations = 40,
                mCostInKibibyte = 65536,
                parallelism = 8,
                hashLengthInBytes = 32,
                version = Argon2Version.V13
            )

            val rawHash = result.rawHashAsByteArray()
//            Log.d("myLogs", "rawHash length: ${rawHash.size}; content: ${rawHash.contentToString()}")

            SecretKeySpec(rawHash, "AES")
        }
    }
}