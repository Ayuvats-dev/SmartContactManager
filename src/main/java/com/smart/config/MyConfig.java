package com.smart.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class MyConfig extends WebSecurityConfigurerAdapter {
@Bean
	public UserDetailsService getUserDetailsService(){
		return new UserDetailsServiceImpl() ;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {

		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(this.getUserDetailsService());
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		return daoAuthenticationProvider;

	}

	/// configure method...

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		        .antMatchers("/admin/**").hasRole("ADMIN")
				.antMatchers("/user/**").hasRole("USER")
				.antMatchers("/**").permitAll()
				.and().formLogin()
//				formLogin() tells that there is form based login
//				.loginPage("/login")
//
//		        .loginPage("/login") this redirects the user to the custom login
//		         page URL
//		        specified in the .loginPage.
//		        spring intercepts the incoming "protected" HTTP request before it
//				reaches your
//				application's controller(getmapping)and redirect to your custom login
//				page
//				if developer is using default login page of spring
//				then no need to use .loginPage("/login"),spring will automatically
//				intercept protected http req and redirect to default login page
//				and /login is itself default protected http req so when user click on
//				login to get the login form ,spring will intrcept that request before
//				 reaching to contoller and redirects the user to the custom login
//				 page URL specified in the .loginPage or redirect to default login page
//				 either redirect to custom
				.loginProcessingUrl("/dologin")
//			    /dologin: When a user submits the login form, it sends a
//			     POST request to the URL defined here.
//			     validates the user's credentials, and performs the actual login process.
//			     It's the endpoint where Spring Security processes the login attempt.
//	             but it is for free no controller required for /dologin,
//	             handled by spring only just we have to mention in the login form
//	             that action="{/dologin}" ,method=post

				.defaultSuccessUrl("/user/index")
//				after successful login user will be directed to this url
				.and().csrf().disable();
	}

}
