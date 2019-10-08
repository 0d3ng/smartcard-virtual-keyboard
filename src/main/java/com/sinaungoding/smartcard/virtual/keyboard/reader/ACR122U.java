package com.sinaungoding.smartcard.virtual.keyboard.reader;

import com.sinaungoding.smartcard.presensi.util.HexUtils;

import javax.smartcardio.*;
import java.util.Arrays;
import java.util.logging.Logger;

public class ACR122U {

    public static final byte[] keyA = {
        (byte) 0x05, (byte) 0x20, (byte) 0x84, (byte) 0x84, (byte) 0x20, (byte) 0x05
    };
    public static final byte[] keyB = {
        (byte) 0x05, (byte) 0x05, (byte) 0x20, (byte) 0x20, (byte) 0x84, (byte) 0x84
    };

    public static final byte[] defaultKeyA = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };
    public static final byte[] defaultKeyB = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    protected byte numberBytesToReadAndWrite = 0x10; // 16 Bytes

    private CardChannel channel;

    private byte[] UID;
    
    Logger log = Logger.getLogger(ACR122U.class.getName());

    public ACR122U() throws Exception {
        CardTerminals terminals = TerminalFactory.getDefault().terminals();
        CardTerminal terminal = null;
        try {
            terminal = terminals.list().get(0);
            log.info(terminal.getName());
            Card card = terminal.connect("*");
            channel = card.getBasicChannel();
        } catch (CardException e) {
            throw e;
        }

    }

    public String getUID() throws Exception {
        byte[] cmd
                = new byte[]{(byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x09, (byte) 0xD4, (byte) 0x60, (byte) 0x01, (byte) 0x01,
                    (byte) 0x20, (byte) 0x23, (byte) 0x11, (byte) 0x04, (byte) 0x10, (byte) 0x00};
        CommandAPDU command = new CommandAPDU(cmd);
        ResponseAPDU response = null;
        try {
            response = channel.transmit(command);
            log.info("cmd >> " + HexUtils.bytesToHexString(cmd));
            log.info("ReadUID << " + HexUtils.bytesToHexString(response.getBytes()));
            if (response.getSW1() == 0x90 && response.getSW2() == 0x00) {
                if (response.getData()[2] == 0x00) {
                    throw new NoTagException("No Tag");
                }

                byte[] data = response.getData();
                byte[] uid = null;
                switch (data[3]) {
                    case 0x10:
                        if (data[8] == 0x18) {
                            log.info("Mifare 4K");
                        } else {
                            log.info("Mifare 1K");
                        }
                        uid = new byte[data[9]];
                        uid = Arrays.copyOfRange(data, 10, data.length);
                        this.UID = uid;
                        break;
                    case 0x20:
                        uid = new byte[data[9]];
                        log.info("ISO14443-4 Type A");
                        uid = Arrays.copyOfRange(data, 10, 17);
                        break;
                    case 0x23:
                        uid = new byte[data[9]];
                        log.info("ISO14443-4 Type B");
                        uid = data;
                        break;
                    default:
                        log.info("Other Tag");
                        uid = data;
                        break;
                }
                String UID = HexUtils.bytesToHexString(uid);
                log.info(UID);
                log.info("");
                return UID;
            }
        } catch (CardException e) {
            throw e;
        }
        return null;
    }

    public boolean AuthBlock(
            byte sectorAddress,
            byte[] key,
            byte keyType) throws Exception {
        // Load Authentication Keys to Reader
        byte[] buff = new byte[20];
        buff[0] = (byte) 0xFF;
        buff[1] = (byte) 0x00;
        buff[2] = (byte) 0x00;
        buff[3] = (byte) 0x00;
        buff[4] = (byte) 0x0F; // LC
        buff[5] = (byte) 0xD4;
        buff[6] = (byte) 0x40;
        buff[7] = (byte) 0x01;
        buff[8] = keyType;
        buff[9] = sectorAddress;

        if (key.length != 6) {
            throw new CardException("Invalid Key Size");
        }

        // Data Bytes (6 Bytes)
        buff[10] = key[0];
        buff[11] = key[1];
        buff[12] = key[2];
        buff[13] = key[3];
        buff[14] = key[4];
        buff[15] = key[5];

        // 4 byte UID
        buff[16] = UID[0];
        buff[17] = UID[1];
        buff[18] = UID[2];
        buff[19] = UID[3];

        CommandAPDU command = new CommandAPDU(buff);
        ResponseAPDU response = null;
        try {
            response = channel.transmit(command);
            log.info("Cmd >> " + HexUtils.bytesToHexString(buff));
            log.info("AuthKey << " + HexUtils.bytesToHexString(response.getBytes()));
            if (response.getSW1() == 0x90 && response.getSW2() == 0x00) {
                log.info(HexUtils.bytesToHexString(response.getData()));
                if (response.getData()[2] == 0x00) {
                    log.info("");
                    return true;
                }
            }
        } catch (CardException e) {
            throw e;
        }
        return false;
    }

    public byte[] ReadBlock(
            byte blockAddress
    ) throws Exception {

        byte[] buffAPDURead = new byte[10];
        buffAPDURead[0] = (byte) 0xFF;
        buffAPDURead[1] = (byte) 0x00;
        buffAPDURead[2] = (byte) 0x00;
        buffAPDURead[3] = (byte) 0x00;
        buffAPDURead[4] = (byte) 0x05;
        buffAPDURead[5] = (byte) 0xD4;
        buffAPDURead[6] = (byte) 0x40;
        buffAPDURead[7] = (byte) 0x01;
        buffAPDURead[8] = (byte) 0x30;
        buffAPDURead[9] = blockAddress;

        CommandAPDU command = new CommandAPDU(buffAPDURead);
        ResponseAPDU response = null;
        try {
            response = channel.transmit(command);
            log.info("cmd >> " + HexUtils.bytesToHexString(buffAPDURead));
            log.info("ReadBlock << " + HexUtils.bytesToHexString(response.getBytes()));
            if (response.getSW1() == 0x90 && response.getSW2() == 0x00) {
                log.info(HexUtils.bytesToHexString(response.getData()));
                buffAPDURead = new byte[5];
                buffAPDURead[0] = (byte) 0xFF;
                buffAPDURead[1] = (byte) 0xC0;
                buffAPDURead[2] = (byte) 0x00;
                buffAPDURead[3] = (byte) 0x00;
                buffAPDURead[4] = (byte) 0x05;
                response = channel.transmit(command);
                log.info("cmd >> " + HexUtils.bytesToHexString(buffAPDURead));
                log.info("ReadBlock << " + HexUtils.bytesToHexString(response.getBytes()));
                if (response.getSW1() == 0x90 && response.getSW2() == 0x00 && response.getData()[2] == 0x00) {
                    byte[] data = Arrays.copyOfRange(response.getData(), 3, response.getData().length);
                    log.info("data << " + HexUtils.bytesToHexString(data));
                    log.info("");
                    return data;
                }
            }
        } catch (CardException e) {
            throw e;
        }
        return null;
    }

    public boolean WriteBlock(
            byte blockAddress,
            byte[] data
    ) throws Exception {

        byte[] buffAPDUWrite = new byte[26];

        buffAPDUWrite[0] = (byte) 0xFF;
        buffAPDUWrite[1] = (byte) 0x00;
        buffAPDUWrite[2] = (byte) 0x00;
        buffAPDUWrite[3] = (byte) 0x00;
        buffAPDUWrite[4] = (byte) 0x15;
        buffAPDUWrite[5] = (byte) 0xD4;
        buffAPDUWrite[6] = (byte) 0x40;
        buffAPDUWrite[7] = (byte) 0x01;
        buffAPDUWrite[8] = (byte) 0xA0;
        buffAPDUWrite[9] = blockAddress;

        if (data.length > this.numberBytesToReadAndWrite) {
            throw new CardException("Write Invalid Buffer Size");
        }

        for (int i = 0; i < data.length; i++) {
            buffAPDUWrite[10 + i] = 0x00;
        }

        for (int i = 0; i < data.length; i++) {
            buffAPDUWrite[10 + i] = data[i];
        }

        CommandAPDU command = new CommandAPDU(buffAPDUWrite);
        ResponseAPDU response = null;
        try {
            response = channel.transmit(command);
            log.info("cmd >> " + HexUtils.bytesToHexString(buffAPDUWrite));
            log.info("WriteBlock << " + HexUtils.bytesToHexString(response.getBytes()));
            if (response.getSW1() == 0x90 && response.getSW2() == 0x00) {
                log.info(HexUtils.bytesToHexString(response.getData()));
                buffAPDUWrite = new byte[5];
                buffAPDUWrite[0] = (byte) 0xFF;
                buffAPDUWrite[1] = (byte) 0xC0;
                buffAPDUWrite[2] = (byte) 0x00;
                buffAPDUWrite[3] = (byte) 0x00;
                buffAPDUWrite[4] = (byte) 0x05;
                command = new CommandAPDU(buffAPDUWrite);
                response = channel.transmit(command);
                log.info("cmd >> " + HexUtils.bytesToHexString(buffAPDUWrite));
                log.info("WriteBlock << " + HexUtils.bytesToHexString(response.getBytes()));
                if (response.getSW1() == 0x90 && response.getSW2() == 0x00 && response.getData()[2] == 0x00) {
                    log.info("");
                    return true;
                }
            }
        } catch (CardException e) {
            throw e;
        }
        return false;
    }
}
