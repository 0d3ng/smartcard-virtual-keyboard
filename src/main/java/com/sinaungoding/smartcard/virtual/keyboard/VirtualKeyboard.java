/*
 * smartcard-virtual-keyboard

 * Copyright (c) 2019
 * All rights reserved.
 * Written by od3ng created on Oct 8, 2019 9:57:11 AM
 * Blog    : sinaungoding.com
 * Email   : lepengdados@gmail.com
 * Github  : 0d3ng
 * Hp      : 085878554150
 */
package com.sinaungoding.smartcard.virtual.keyboard;

import com.sinaungoding.smartcard.virtual.keyboard.reader.ACR122U;
import java.awt.AWTException;
import java.awt.Robot;
import java.awt.event.KeyEvent;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author od3ng
 */
public class VirtualKeyboard {
    
    static Logger log = Logger.getLogger(VirtualKeyboard.class.getName());
    
    public static void main(String[] args) {
        try {
            Robot robot = new Robot();
            robot.setAutoDelay(50);
            ACR122U reader = new ACR122U();
            new Thread(() -> {
                String UID = null;
                while (true) {
                    try {
                        String uid = reader.getUID();
                        if (!uid.equals(UID)) {
                            for (char c : uid.toCharArray()) {
                                robot.keyPress(c);
                                robot.delay(100);
                                robot.keyRelease(c);
                                robot.delay(100);
                            }
                            robot.keyPress(KeyEvent.VK_ENTER);
                        }
                    } catch (Exception ex) {
                        log.log(Level.SEVERE, ex.getMessage());
                        UID = null;
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException ex) {
                        log.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
            }).start();
            
        } catch (AWTException ex) {
            log.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            log.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }
}
