package com.poc.payments.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/payments")
public class PaymentController {

    @GetMapping("/health")
    public String health() {
        return "Payments POC is running";
    }


    @GetMapping("/secure")
    public String securePayment() {
        return "Payment API: Access Token successfully validated by WAM";
    }
}