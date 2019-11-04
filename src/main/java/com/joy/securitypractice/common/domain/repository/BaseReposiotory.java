package com.joy.securitypractice.common.domain.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BaseReposiotory<T> {
    /**
     * 通过id查询
     */
    T findAllById(Long id);

    /**
     * 分页查询
     */
    Page<T> findAll(Specification specification, Pageable pageable);

    /**
     * 排序并获取所有数据的查询
     */
    List<T> findAll(Specification<T> spec, Sort sort);


    /**
     * 获取所有的查询
     */
    List<T> findAll(Specification<T> spec);
}
