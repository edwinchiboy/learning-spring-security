package com.in28minutes.learn_spring_security.resources;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController

public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass());

    public static final List<Todo> TODOS = List.of(new Todo("in28Minutes", "learn AWS"), new Todo("in28Minutes", "Get AWS Certified "));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return TODOS;
    }

    @GetMapping("/users/{userName}/todos")
    @PreAuthorize("hasRole('USER) and #username == authentication.name")
    @PostAuthorize("returnObject.name == 'in28minutes'")
    @RolesAllowed({"ADMIN","USER"})
    @Secured({"ROLE_ADMIN","ROLE_USER"})

    public Todo retrieveTodosForASpecificUser(@PathVariable String userName) {
        return TODOS.get(0);
    }

    @PostMapping("/users/{userName}/todos")
    public void createTodosForASpecificUser(@PathVariable String userName, @RequestBody Todo todo) {
        logger.info("Creat {} for  {}", todo, userName);

    }
}

record Todo(String userName, String description) {
}
