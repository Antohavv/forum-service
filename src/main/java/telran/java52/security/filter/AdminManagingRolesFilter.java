package telran.java52.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import telran.java52.accounting.dao.UserAccountRepository;
import telran.java52.accounting.dto.exceptions.IncorrectRoleException;
import telran.java52.accounting.model.Role;
import telran.java52.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
@Order(20)
public class AdminManagingRolesFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
	

		if (checkEndpoint(request.getMethod(), request.getServletPath())) {
			try {
				Principal principal = request.getUserPrincipal();
				String userName = principal.getName();
				UserAccount userAccount = userAccountRepository.findById(userName)
															   .orElseThrow(RuntimeException::new);
				if (!userAccount.getRoles().contains(Role.ADMINISTRATOR)) {
					throw new RuntimeException();
				}
			} catch (Exception e) {
				response.sendError(409);
			}
		}

		chain.doFilter(request, response);
	}

	private boolean checkEndpoint(String method, String path) {
		String rolePatern = "/account/user/.+/role/.+$";
		return ((HttpMethod.PUT.matches(method) || HttpMethod.DELETE.matches(method)) && path.matches(rolePatern));
	}

}