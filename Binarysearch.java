/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.binarysearch;

/**
 *
 * @author mphoyanga
 */
import java.util.Scanner;
public class Binarysearch{
    public static void main (String[]args){
        
        Scanner obj=new Scanner(System.in);
        
        System.out.println("Enter the ID of the product you are looking or:");
        int targetID=obj.nextInt();
        
        int[] productIDs ={104,105,106,107,101,102,103};
        
        int results=findProductIndex(productIDs,targetID);
         
         if(results!=-1){
             System.out.println("The product ID index: " + results);
         }
         else{
             System.out.println("ID not found.");
         }
    }
    
    public static int findProductIndex(int[]productIDs,int targetID){
        
        int low=0;
        int high=productIDs.length-1;
        
        while(low<=high){
            int mid=low+(high-low)/2;
        
            
            if(productIDs[mid]==targetID){
                return mid;
            }
                else if(productIDs[mid]<targetID){
                    low=mid+1;
                        
                    }
                    else{
                        high=mid-1;
                    }
               
            }
             return-1;
    }
    
}