package me.kimsmile.tutorial;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "me.kimsmile.tutorial.*")
public class JwtTutorialApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtTutorialApplication.class, args);
	}

}
