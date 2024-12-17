package com.ruoyi;


import com.mysql.cj.protocol.Security;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class MysqlNativePassword {


    public static void main(String[] args)  {
        int begin = 3;
        int end = 5;
        //秘钥
        String challengeHex = "4d0853767947065952771c3d27167a25402d4a57";
        //密文
        String encString = "a7a3eddab29967f56ed44307051190cb0ebb16a8";

        testCrack(begin, end, challengeHex, encString);

//        generatePasswords();
    }

    public static byte[] authenticate(String serverChallenge, String password) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String encoding = "UTF-8";
        return Security.scramble411(password, serverChallenge.getBytes(StandardCharsets.ISO_8859_1), encoding);
    }

    public static byte[] authenticateCache(String serverChallenge,String password) {
        try {
            return Security.scrambleCachingSha2(password.getBytes("UTF-8"), serverChallenge.getBytes());
        } catch (UnsupportedEncodingException | DigestException var3) {
            return null;
        }
    }

    /**
     * 加密功能测试
     */
    public static void testEnc(String[] args) throws UnsupportedEncodingException, DecoderException, NoSuchAlgorithmException, ExecutionException, InterruptedException {

        // 加密功能测试
        MysqlNativePassword password = new MysqlNativePassword();
        String mysqlNativePassword = getMysqlNativePassword("4d0853767947065952771c3d27167a25402d4a57", "root");
        //a7a3eddab29967f56ed44307051190cb0ebb16a8
        System.out.println(mysqlNativePassword);
        String cachingSha2 = getCachingSha2("4d0853767947065952771c3d27167a25402d4a57", "root");
        //5de7850acb692b03ede5991044ab05c0d7e42a739fa9e3f0380b20b6850d8d10
        System.out.println(cachingSha2);
    }


    /**
     *  从某一个长度开始暴力破解
     */
    public static void testCrack(int begin, int end, String challengeHex, String encString) {
        //字符集
        ArrayList<Character> characters = new ArrayList<>(Arrays.asList(
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
                , 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                ,'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
                //特殊字符 ! @ # $ % ^ & * ( ) - _ = + [ { ] } \ | ; : ' " , < . > / ? ~ `` `
                ,'!','@','#','$','%','^','&','*','(',')','-', '_', '=', '+', '[', '{', ']', '}', '\\', '|', ';', ':','\'', '"', ',', '<', '.', '>', '/', '?', '~', '`'
        ));

        /// 创建一个固定大小的线程池
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        // 创建 CompletionService 来管理任务的完成顺序
        CompletionService<Boolean> completionService = new ExecutorCompletionService<>(executor);

        // 提交任务到线程池
        for (int i = begin; i <= end; i++) {
            final int length = i; // 确保 lambda 表达式中的变量是有效的
            completionService.submit(() -> {
                Instant start = Instant.now();
                boolean flag = generatePermutationsWithRepetitionNonRecursive(characters, length, challengeHex, encString);
                Instant endTime = Instant.now();
                Duration duration = Duration.between(start, endTime);
                System.out.println("Length " + length + ": time: " + duration.toMillis() + " ms");
                return flag;
            });
        }

        // 按照任务完成的顺序检查结果
        boolean found = false;
        for (int i = 0; i < (end - begin + 1); i++) {
            try {
                Future<Boolean> future = completionService.take(); // 阻塞等待下一个完成的任务
                if (future.get()) { // 如果某个任务返回 true
                    found = true;
                    break;
                }
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }

        // 如果找到了满足条件的排列，取消所有未完成的任务
        if (found) {
            executor.shutdownNow(); // 尝试中断所有正在运行的任务
        } else {
            executor.shutdown(); // 正常关闭线程池
        }

        if (found) {
            System.out.println("Solution found!");
        } else {
            System.out.println("No solution found.");
        }
    }



    private static boolean generatePermutationsWithRepetitionNonRecursive(List<Character> characters, int k,String challengeHex, String encString) throws DecoderException, UnsupportedEncodingException, NoSuchAlgorithmException {
        Deque<List<Character>> stack = new LinkedList<>();
        stack.push(new ArrayList<>()); // 初始状态：空排列

        while (!stack.isEmpty()) {
            List<Character> current = stack.pop();

            if (current.size() == k) {
                String passwordTry = current.stream().map(String::valueOf).collect(Collectors.joining());
                String mysqlNativePassword = getMysqlNativePassword(challengeHex, passwordTry);
                //和密文做对比
                if (encString.equals(mysqlNativePassword)){
                    System.out.println("password: " + passwordTry);
                    return true;
                }
            } else {
                for (Character character : characters) {
                    List<Character> next = new ArrayList<>(current);
                    next.add(character);
                    stack.push(next);
                }
            }

            // 定期检查是否被中断
            if (Thread.interrupted()) {
                break; // 提前退出循环
            }
        }
        return false;
    }
    public static  void generatePasswords(){
        //字符集
        ArrayList<Character> characters = new ArrayList<>(Arrays.asList(
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
                , 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                ,'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
                //特殊字符 ! @ # $ % ^ & * ( ) - _ = + [ { ] } \ | ; : ' " , < . > / ? ~ `` `
                ,'!','@','#','$','%','^','&','*','(',')','-', '_', '=', '+', '[', '{', ']', '}', '\\', '|', ';', ':','\'', '"', ',', '<', '.', '>', '/', '?', '~', '`'
        ));
        ArrayList<String> strings = generatePasswordsWithRepetitionNonRecursive(characters,5);
        System.out.println(strings);
        System.out.println(strings.size());
    }

    private static ArrayList<String> generatePasswordsWithRepetitionNonRecursive(List<Character> characters, int k)  {
        ArrayList<String> passwords = new ArrayList<>();
        Deque<List<Character>> stack = new LinkedList<>();
        stack.push(new ArrayList<>()); // 初始状态：空排列

        while (!stack.isEmpty()) {
            List<Character> current = stack.pop();

            if (current.size() == k) {
                String passwordTry = current.stream().map(String::valueOf).collect(Collectors.joining());
                passwords.add(passwordTry);
            } else {
                for (Character character : characters) {
                    List<Character> next = new ArrayList<>(current);
                    next.add(character);
                    stack.push(next);
                }
            }

            // 定期检查是否被中断
            if (Thread.interrupted()) {
                break; // 提前退出循环
            }
        }
        return passwords;
    }

    private static void generatePermutationsWithRepetition(List<Character> characters, int k, List<Character> current, List<List<Character>> allPermutations) {
        if (current.size() == k) {
            allPermutations.add(new ArrayList<>(current));
            return;
        }

        for (Character character : characters) {
            // 选择一个字符
            current.add(character);
            // 继续生成排列，仍然可以从所有字符中选择
            generatePermutationsWithRepetition(characters, k, current, allPermutations);
            // 回溯：移除最后添加的字符，尝试其他可能性
            current.remove(current.size() - 1);
        }
    }

    private static String getCachingSha2(String challengeHex, String password) throws DecoderException {
        byte[] bytes;
        String challenge;

        //Server Greeting  中的密钥是两段salt拼接到一起的
        //5de7850acb692b03ede5991044ab05c0d7e42a739fa9e3f0380b20b6850d8d10 密码密文。
        bytes = Hex.decodeHex(challengeHex);
        challenge = new String(bytes, StandardCharsets.ISO_8859_1);
        byte[] roots = authenticateCache(challenge, password);
        String string = Hex.encodeHexString(roots);
//        System.out.println(string);
        return string;
    }

    private static String getMysqlNativePassword(String challengeHex,String password) throws DecoderException, UnsupportedEncodingException, NoSuchAlgorithmException {

        byte[] bytes = Hex.decodeHex(challengeHex);
        String challenge = new String(bytes, StandardCharsets.ISO_8859_1);
        byte[] authenticate = authenticate(challenge,password);
        //a7a3eddab29967f56ed44307051190cb0ebb16a8 密码密文。
        String string = Hex.encodeHexString(authenticate);
//        System.out.println(string);
        return string;
    }

}