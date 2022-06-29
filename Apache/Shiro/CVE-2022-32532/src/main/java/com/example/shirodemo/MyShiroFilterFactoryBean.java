package com.example.shirodemo;

import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.RegExPatternMatcher;
import org.apache.shiro.web.filter.mgt.*;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;


public class MyShiroFilterFactoryBean extends ShiroFilterFactoryBean {

    public MyShiroFilterFactoryBean() {
        super();
    }

    @Override
    protected AbstractShiroFilter createInstance() {
        SecurityManager securityManager = this.getSecurityManager();
        FilterChainManager manager = new DefaultFilterChainManager();
        manager.addFilter("myFilter",new MyFilter());
        // my filter
        manager.addToChain("/permit/.*", "myFilter");
        // todo: add other filters

        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
        chainResolver.setFilterChainManager(manager);
        // set RegExPatternMatcher
        chainResolver.setPathMatcher(new RegExPatternMatcher());
        return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);
    }

    static class SpringShiroFilter extends AbstractShiroFilter {
        protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {
            this.setSecurityManager(webSecurityManager);
            this.setFilterChainResolver(resolver);
        }
    }
}

