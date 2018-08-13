const routers = [
    {
        path: '/',
        meta: {
            title: ''
        },
        component: (resolve) => require(['./views/index.vue'], resolve)
    },
    {
        path: '/test',
        meta: {
            title: 'test title'
        },
        component: (resolve) => require(['./views/test/main.vue'], resolve)
    }
];
export default routers;
