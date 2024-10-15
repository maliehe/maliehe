/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.arraylist;

/**
 *
 * @author mphoyanga
 */
import java.util.ArrayList;

public class Arraylist {

    public static void main(String[] args) {
        
        ArrayList<String> names=new ArrayList<>();
        
        names.add("Mpho");
        names.add("Glory");
        names.add("Khuthadz");
        names.add("Munyai");
        
        System.out.println(names);
        
        //accessing an element
        
        String name=names.get(0);
        
        System.out.println(name);
        
        //exchanging elements
        
        names.set(2,"knowledge");
        System.out.println("Updated array:"+names);
        
        //removing an element
        
        String str=names.remove(3);
        System.out.println("worthy names array:" +names);
        System.out.println("Removed element:"+str);
        
               
        
    }
}
